rule TTP_XOR_MULT_DOSStub_1c90 {
  strings:
    $key_1c90 = { 48 f8 [2] 3c e0 [2] 7b e2 [2] 3c f3 [2] 72 ff [2] 7e f5 [2] 69 fe [2] 72 b0 [2] 4f }

  condition:
    any of them
}