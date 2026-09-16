rule TTP_XOR_MULT_DOSStub_54b6 {
  strings:
    $key_54b6 = { 00 de [2] 74 c6 [2] 33 c4 [2] 74 d5 [2] 3a d9 [2] 36 d3 [2] 21 d8 [2] 3a 96 [2] 07 }

  condition:
    any of them
}