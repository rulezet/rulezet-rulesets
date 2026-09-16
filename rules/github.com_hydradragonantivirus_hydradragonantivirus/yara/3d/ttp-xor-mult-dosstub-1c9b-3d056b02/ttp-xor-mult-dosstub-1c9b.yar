rule TTP_XOR_MULT_DOSStub_1c9b {
  strings:
    $key_1c9b = { 48 f3 [2] 3c eb [2] 7b e9 [2] 3c f8 [2] 72 f4 [2] 7e fe [2] 69 f5 [2] 72 bb [2] 4f }

  condition:
    any of them
}