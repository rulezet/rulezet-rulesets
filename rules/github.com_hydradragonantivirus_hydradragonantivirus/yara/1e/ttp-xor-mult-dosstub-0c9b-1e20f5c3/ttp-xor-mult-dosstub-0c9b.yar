rule TTP_XOR_MULT_DOSStub_0c9b {
  strings:
    $key_0c9b = { 58 f3 [2] 2c eb [2] 6b e9 [2] 2c f8 [2] 62 f4 [2] 6e fe [2] 79 f5 [2] 62 bb [2] 5f }

  condition:
    any of them
}