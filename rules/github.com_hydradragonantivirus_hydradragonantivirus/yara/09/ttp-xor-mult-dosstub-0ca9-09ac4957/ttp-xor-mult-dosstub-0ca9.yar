rule TTP_XOR_MULT_DOSStub_0ca9 {
  strings:
    $key_0ca9 = { 58 c1 [2] 2c d9 [2] 6b db [2] 2c ca [2] 62 c6 [2] 6e cc [2] 79 c7 [2] 62 89 [2] 5f }

  condition:
    any of them
}