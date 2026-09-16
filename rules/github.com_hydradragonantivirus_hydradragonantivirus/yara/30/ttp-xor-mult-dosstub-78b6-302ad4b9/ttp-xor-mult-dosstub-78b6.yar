rule TTP_XOR_MULT_DOSStub_78b6 {
  strings:
    $key_78b6 = { 2c de [2] 58 c6 [2] 1f c4 [2] 58 d5 [2] 16 d9 [2] 1a d3 [2] 0d d8 [2] 16 96 [2] 2b }

  condition:
    any of them
}