rule TTP_XOR_MULT_DOSStub_1eb6 {
  strings:
    $key_1eb6 = { 4a de [2] 3e c6 [2] 79 c4 [2] 3e d5 [2] 70 d9 [2] 7c d3 [2] 6b d8 [2] 70 96 [2] 4d }

  condition:
    any of them
}