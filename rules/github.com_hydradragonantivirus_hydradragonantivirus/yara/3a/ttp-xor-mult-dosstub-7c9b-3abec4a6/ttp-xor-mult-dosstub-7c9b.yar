rule TTP_XOR_MULT_DOSStub_7c9b {
  strings:
    $key_7c9b = { 28 f3 [2] 5c eb [2] 1b e9 [2] 5c f8 [2] 12 f4 [2] 1e fe [2] 09 f5 [2] 12 bb [2] 2f }

  condition:
    any of them
}