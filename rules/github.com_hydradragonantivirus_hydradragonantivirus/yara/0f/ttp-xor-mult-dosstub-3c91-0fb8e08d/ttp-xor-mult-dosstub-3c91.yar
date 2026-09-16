rule TTP_XOR_MULT_DOSStub_3c91 {
  strings:
    $key_3c91 = { 68 f9 [2] 1c e1 [2] 5b e3 [2] 1c f2 [2] 52 fe [2] 5e f4 [2] 49 ff [2] 52 b1 [2] 6f }

  condition:
    any of them
}