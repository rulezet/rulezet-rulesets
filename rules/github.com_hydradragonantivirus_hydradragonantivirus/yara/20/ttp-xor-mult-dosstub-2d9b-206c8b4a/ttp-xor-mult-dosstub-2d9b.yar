rule TTP_XOR_MULT_DOSStub_2d9b {
  strings:
    $key_2d9b = { 79 f3 [2] 0d eb [2] 4a e9 [2] 0d f8 [2] 43 f4 [2] 4f fe [2] 58 f5 [2] 43 bb [2] 7e }

  condition:
    any of them
}