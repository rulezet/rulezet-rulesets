rule TTP_XOR_MULT_DOSStub_14f9 {
  strings:
    $key_14f9 = { 40 91 [2] 34 89 [2] 73 8b [2] 34 9a [2] 7a 96 [2] 76 9c [2] 61 97 [2] 7a d9 [2] 47 }

  condition:
    any of them
}