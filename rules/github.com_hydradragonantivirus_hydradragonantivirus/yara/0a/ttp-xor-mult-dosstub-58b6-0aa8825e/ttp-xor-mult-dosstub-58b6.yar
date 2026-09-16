rule TTP_XOR_MULT_DOSStub_58b6 {
  strings:
    $key_58b6 = { 0c de [2] 78 c6 [2] 3f c4 [2] 78 d5 [2] 36 d9 [2] 3a d3 [2] 2d d8 [2] 36 96 [2] 0b }

  condition:
    any of them
}