rule TTP_XOR_MULT_DOSStub_1cb6 {
  strings:
    $key_1cb6 = { 48 de [2] 3c c6 [2] 7b c4 [2] 3c d5 [2] 72 d9 [2] 7e d3 [2] 69 d8 [2] 72 96 [2] 4f }

  condition:
    any of them
}