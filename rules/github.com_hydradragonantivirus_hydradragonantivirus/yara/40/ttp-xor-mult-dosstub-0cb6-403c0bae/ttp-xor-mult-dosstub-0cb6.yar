rule TTP_XOR_MULT_DOSStub_0cb6 {
  strings:
    $key_0cb6 = { 58 de [2] 2c c6 [2] 6b c4 [2] 2c d5 [2] 62 d9 [2] 6e d3 [2] 79 d8 [2] 62 96 [2] 5f }

  condition:
    any of them
}