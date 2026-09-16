rule TTP_XOR_MULT_DOSStub_489b {
  strings:
    $key_489b = { 1c f3 [2] 68 eb [2] 2f e9 [2] 68 f8 [2] 26 f4 [2] 2a fe [2] 3d f5 [2] 26 bb [2] 1b }

  condition:
    any of them
}