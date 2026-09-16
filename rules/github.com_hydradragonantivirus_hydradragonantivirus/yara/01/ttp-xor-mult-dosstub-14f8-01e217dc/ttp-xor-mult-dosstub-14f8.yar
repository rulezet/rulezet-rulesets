rule TTP_XOR_MULT_DOSStub_14f8 {
  strings:
    $key_14f8 = { 40 90 [2] 34 88 [2] 73 8a [2] 34 9b [2] 7a 97 [2] 76 9d [2] 61 96 [2] 7a d8 [2] 47 }

  condition:
    any of them
}