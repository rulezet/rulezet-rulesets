rule TTP_XOR_MULT_DOSStub_4e9b {
  strings:
    $key_4e9b = { 1a f3 [2] 6e eb [2] 29 e9 [2] 6e f8 [2] 20 f4 [2] 2c fe [2] 3b f5 [2] 20 bb [2] 1d }

  condition:
    any of them
}