rule TTP_XOR_MULT_DOSStub_089b {
  strings:
    $key_089b = { 5c f3 [2] 28 eb [2] 6f e9 [2] 28 f8 [2] 66 f4 [2] 6a fe [2] 7d f5 [2] 66 bb [2] 5b }

  condition:
    any of them
}