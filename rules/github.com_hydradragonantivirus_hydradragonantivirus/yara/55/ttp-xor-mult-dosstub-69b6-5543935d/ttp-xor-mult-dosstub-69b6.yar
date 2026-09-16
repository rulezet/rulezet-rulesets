rule TTP_XOR_MULT_DOSStub_69b6 {
  strings:
    $key_69b6 = { 3d de [2] 49 c6 [2] 0e c4 [2] 49 d5 [2] 07 d9 [2] 0b d3 [2] 1c d8 [2] 07 96 [2] 3a }

  condition:
    any of them
}