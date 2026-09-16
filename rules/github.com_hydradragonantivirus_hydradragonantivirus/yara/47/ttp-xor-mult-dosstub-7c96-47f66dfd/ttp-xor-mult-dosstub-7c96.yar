rule TTP_XOR_MULT_DOSStub_7c96 {
  strings:
    $key_7c96 = { 28 fe [2] 5c e6 [2] 1b e4 [2] 5c f5 [2] 12 f9 [2] 1e f3 [2] 09 f8 [2] 12 b6 [2] 2f }

  condition:
    any of them
}