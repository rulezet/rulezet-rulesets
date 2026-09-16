rule TTP_XOR_MULT_DOSStub_5c90 {
  strings:
    $key_5c90 = { 08 f8 [2] 7c e0 [2] 3b e2 [2] 7c f3 [2] 32 ff [2] 3e f5 [2] 29 fe [2] 32 b0 [2] 0f }

  condition:
    any of them
}