rule TTP_XOR_MULT_DOSStub_7e9b {
  strings:
    $key_7e9b = { 2a f3 [2] 5e eb [2] 19 e9 [2] 5e f8 [2] 10 f4 [2] 1c fe [2] 0b f5 [2] 10 bb [2] 2d }

  condition:
    any of them
}