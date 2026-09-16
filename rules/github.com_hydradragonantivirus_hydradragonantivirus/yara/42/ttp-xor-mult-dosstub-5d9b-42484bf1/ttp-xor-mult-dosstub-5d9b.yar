rule TTP_XOR_MULT_DOSStub_5d9b {
  strings:
    $key_5d9b = { 09 f3 [2] 7d eb [2] 3a e9 [2] 7d f8 [2] 33 f4 [2] 3f fe [2] 28 f5 [2] 33 bb [2] 0e }

  condition:
    any of them
}