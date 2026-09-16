rule TTP_XOR_MULT_DOSStub_4c9b {
  strings:
    $key_4c9b = { 18 f3 [2] 6c eb [2] 2b e9 [2] 6c f8 [2] 22 f4 [2] 2e fe [2] 39 f5 [2] 22 bb [2] 1f }

  condition:
    any of them
}