rule TTP_XOR_MULT_DOSStub_5c96 {
  strings:
    $key_5c96 = { 08 fe [2] 7c e6 [2] 3b e4 [2] 7c f5 [2] 32 f9 [2] 3e f3 [2] 29 f8 [2] 32 b6 [2] 0f }

  condition:
    any of them
}