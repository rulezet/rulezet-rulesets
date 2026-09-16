rule TTP_XOR_MULT_DOSStub_14f5 {
  strings:
    $key_14f5 = { 40 9d [2] 34 85 [2] 73 87 [2] 34 96 [2] 7a 9a [2] 76 90 [2] 61 9b [2] 7a d5 [2] 47 }

  condition:
    any of them
}