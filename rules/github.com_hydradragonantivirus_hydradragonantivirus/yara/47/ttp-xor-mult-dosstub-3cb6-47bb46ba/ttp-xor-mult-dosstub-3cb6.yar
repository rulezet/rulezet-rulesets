rule TTP_XOR_MULT_DOSStub_3cb6 {
  strings:
    $key_3cb6 = { 68 de [2] 1c c6 [2] 5b c4 [2] 1c d5 [2] 52 d9 [2] 5e d3 [2] 49 d8 [2] 52 96 [2] 6f }

  condition:
    any of them
}