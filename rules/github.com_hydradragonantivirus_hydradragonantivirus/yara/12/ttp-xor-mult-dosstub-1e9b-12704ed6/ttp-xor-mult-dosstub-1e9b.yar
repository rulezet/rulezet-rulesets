rule TTP_XOR_MULT_DOSStub_1e9b {
  strings:
    $key_1e9b = { 4a f3 [2] 3e eb [2] 79 e9 [2] 3e f8 [2] 70 f4 [2] 7c fe [2] 6b f5 [2] 70 bb [2] 4d }

  condition:
    any of them
}