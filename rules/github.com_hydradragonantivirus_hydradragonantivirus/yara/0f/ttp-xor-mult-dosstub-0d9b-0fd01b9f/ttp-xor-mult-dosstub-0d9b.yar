rule TTP_XOR_MULT_DOSStub_0d9b {
  strings:
    $key_0d9b = { 59 f3 [2] 2d eb [2] 6a e9 [2] 2d f8 [2] 63 f4 [2] 6f fe [2] 78 f5 [2] 63 bb [2] 5e }

  condition:
    any of them
}