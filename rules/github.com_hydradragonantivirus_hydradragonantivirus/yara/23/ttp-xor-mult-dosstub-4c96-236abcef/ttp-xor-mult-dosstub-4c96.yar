rule TTP_XOR_MULT_DOSStub_4c96 {
  strings:
    $key_4c96 = { 18 fe [2] 6c e6 [2] 2b e4 [2] 6c f5 [2] 22 f9 [2] 2e f3 [2] 39 f8 [2] 22 b6 [2] 1f }

  condition:
    any of them
}