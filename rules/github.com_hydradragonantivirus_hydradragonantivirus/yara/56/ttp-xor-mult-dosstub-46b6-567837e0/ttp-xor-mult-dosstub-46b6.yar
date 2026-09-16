rule TTP_XOR_MULT_DOSStub_46b6 {
  strings:
    $key_46b6 = { 12 de [2] 66 c6 [2] 21 c4 [2] 66 d5 [2] 28 d9 [2] 24 d3 [2] 33 d8 [2] 28 96 [2] 15 }

  condition:
    any of them
}