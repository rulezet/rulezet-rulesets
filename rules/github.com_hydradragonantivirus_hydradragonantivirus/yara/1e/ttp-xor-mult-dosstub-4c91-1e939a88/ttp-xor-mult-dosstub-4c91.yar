rule TTP_XOR_MULT_DOSStub_4c91 {
  strings:
    $key_4c91 = { 18 f9 [2] 6c e1 [2] 2b e3 [2] 6c f2 [2] 22 fe [2] 2e f4 [2] 39 ff [2] 22 b1 [2] 1f }

  condition:
    any of them
}