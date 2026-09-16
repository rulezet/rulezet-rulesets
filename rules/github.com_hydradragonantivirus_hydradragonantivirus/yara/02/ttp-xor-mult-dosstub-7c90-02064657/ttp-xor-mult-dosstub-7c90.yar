rule TTP_XOR_MULT_DOSStub_7c90 {
  strings:
    $key_7c90 = { 28 f8 [2] 5c e0 [2] 1b e2 [2] 5c f3 [2] 12 ff [2] 1e f5 [2] 09 fe [2] 12 b0 [2] 2f }

  condition:
    any of them
}