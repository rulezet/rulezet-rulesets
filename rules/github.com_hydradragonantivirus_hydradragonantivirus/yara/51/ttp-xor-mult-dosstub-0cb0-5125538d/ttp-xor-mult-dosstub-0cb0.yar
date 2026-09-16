rule TTP_XOR_MULT_DOSStub_0cb0 {
  strings:
    $key_0cb0 = { 58 d8 [2] 2c c0 [2] 6b c2 [2] 2c d3 [2] 62 df [2] 6e d5 [2] 79 de [2] 62 90 [2] 5f }

  condition:
    any of them
}