rule TTP_XOR_MULT_DOSStub_20b6 {
  strings:
    $key_20b6 = { 74 de [2] 00 c6 [2] 47 c4 [2] 00 d5 [2] 4e d9 [2] 42 d3 [2] 55 d8 [2] 4e 96 [2] 73 }

  condition:
    any of them
}