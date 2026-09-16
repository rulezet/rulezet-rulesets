rule TTP_XOR_MULT_DOSStub_0c90 {
  strings:
    $key_0c90 = { 58 f8 [2] 2c e0 [2] 6b e2 [2] 2c f3 [2] 62 ff [2] 6e f5 [2] 79 fe [2] 62 b0 [2] 5f }

  condition:
    any of them
}