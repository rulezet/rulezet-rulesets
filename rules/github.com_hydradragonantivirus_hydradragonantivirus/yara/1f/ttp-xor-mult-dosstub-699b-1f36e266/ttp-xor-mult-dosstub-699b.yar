rule TTP_XOR_MULT_DOSStub_699b {
  strings:
    $key_699b = { 3d f3 [2] 49 eb [2] 0e e9 [2] 49 f8 [2] 07 f4 [2] 0b fe [2] 1c f5 [2] 07 bb [2] 3a }

  condition:
    any of them
}