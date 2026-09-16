rule TTP_XOR_MULT_DOSStub_0c91 {
  strings:
    $key_0c91 = { 58 f9 [2] 2c e1 [2] 6b e3 [2] 2c f2 [2] 62 fe [2] 6e f4 [2] 79 ff [2] 62 b1 [2] 5f }

  condition:
    any of them
}