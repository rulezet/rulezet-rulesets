rule TTP_XOR_MULT_DOSStub_2c91 {
  strings:
    $key_2c91 = { 78 f9 [2] 0c e1 [2] 4b e3 [2] 0c f2 [2] 42 fe [2] 4e f4 [2] 59 ff [2] 42 b1 [2] 7f }

  condition:
    any of them
}