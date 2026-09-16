rule TTP_XOR_MULT_DOSStub_4cb6 {
  strings:
    $key_4cb6 = { 18 de [2] 6c c6 [2] 2b c4 [2] 6c d5 [2] 22 d9 [2] 2e d3 [2] 39 d8 [2] 22 96 [2] 1f }

  condition:
    any of them
}