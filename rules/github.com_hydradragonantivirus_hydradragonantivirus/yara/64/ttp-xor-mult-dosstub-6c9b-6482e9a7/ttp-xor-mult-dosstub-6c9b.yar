rule TTP_XOR_MULT_DOSStub_6c9b {
  strings:
    $key_6c9b = { 38 f3 [2] 4c eb [2] 0b e9 [2] 4c f8 [2] 02 f4 [2] 0e fe [2] 19 f5 [2] 02 bb [2] 3f }

  condition:
    any of them
}