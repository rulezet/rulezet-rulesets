rule TTP_XOR_MULT_DOSStub_6cb6 {
  strings:
    $key_6cb6 = { 38 de [2] 4c c6 [2] 0b c4 [2] 4c d5 [2] 02 d9 [2] 0e d3 [2] 19 d8 [2] 02 96 [2] 3f }

  condition:
    any of them
}