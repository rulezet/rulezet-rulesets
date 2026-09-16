rule TTP_XOR_MULT_DOSStub_2c96 {
  strings:
    $key_2c96 = { 78 fe [2] 0c e6 [2] 4b e4 [2] 0c f5 [2] 42 f9 [2] 4e f3 [2] 59 f8 [2] 42 b6 [2] 7f }

  condition:
    any of them
}