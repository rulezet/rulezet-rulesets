rule TTP_XOR_MULT_DOSStub_3d9b {
  strings:
    $key_3d9b = { 69 f3 [2] 1d eb [2] 5a e9 [2] 1d f8 [2] 53 f4 [2] 5f fe [2] 48 f5 [2] 53 bb [2] 6e }

  condition:
    any of them
}