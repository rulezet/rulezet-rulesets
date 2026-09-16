rule TTP_XOR_MULT_DOSStub_2cb6 {
  strings:
    $key_2cb6 = { 78 de [2] 0c c6 [2] 4b c4 [2] 0c d5 [2] 42 d9 [2] 4e d3 [2] 59 d8 [2] 42 96 [2] 7f }

  condition:
    any of them
}