rule TTP_XOR_MULT_DOSStub_5cb6 {
  strings:
    $key_5cb6 = { 08 de [2] 7c c6 [2] 3b c4 [2] 7c d5 [2] 32 d9 [2] 3e d3 [2] 29 d8 [2] 32 96 [2] 0f }

  condition:
    any of them
}