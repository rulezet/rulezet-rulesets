rule TTP_XOR_MULT_DOSStub_5c91 {
  strings:
    $key_5c91 = { 08 f9 [2] 7c e1 [2] 3b e3 [2] 7c f2 [2] 32 fe [2] 3e f4 [2] 29 ff [2] 32 b1 [2] 0f }

  condition:
    any of them
}