rule TTP_XOR_MULT_DOSStub_7cb6 {
  strings:
    $key_7cb6 = { 28 de [2] 5c c6 [2] 1b c4 [2] 5c d5 [2] 12 d9 [2] 1e d3 [2] 09 d8 [2] 12 96 [2] 2f }

  condition:
    any of them
}