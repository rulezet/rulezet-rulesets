rule TTP_XOR_MULT_DOSStub_499b {
  strings:
    $key_499b = { 1d f3 [2] 69 eb [2] 2e e9 [2] 69 f8 [2] 27 f4 [2] 2b fe [2] 3c f5 [2] 27 bb [2] 1a }

  condition:
    any of them
}