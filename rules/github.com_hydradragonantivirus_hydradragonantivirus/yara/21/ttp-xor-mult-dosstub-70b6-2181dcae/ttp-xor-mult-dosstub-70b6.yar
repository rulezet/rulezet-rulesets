rule TTP_XOR_MULT_DOSStub_70b6 {
  strings:
    $key_70b6 = { 24 de [2] 50 c6 [2] 17 c4 [2] 50 d5 [2] 1e d9 [2] 12 d3 [2] 05 d8 [2] 1e 96 [2] 23 }

  condition:
    any of them
}