rule TTP_XOR_MULT_DOSStub_6eb6 {
  strings:
    $key_6eb6 = { 3a de [2] 4e c6 [2] 09 c4 [2] 4e d5 [2] 00 d9 [2] 0c d3 [2] 1b d8 [2] 00 96 [2] 3d }

  condition:
    any of them
}