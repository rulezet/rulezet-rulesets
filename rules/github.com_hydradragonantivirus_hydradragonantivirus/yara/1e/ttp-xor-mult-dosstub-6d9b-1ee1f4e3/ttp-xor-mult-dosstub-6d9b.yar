rule TTP_XOR_MULT_DOSStub_6d9b {
  strings:
    $key_6d9b = { 39 f3 [2] 4d eb [2] 0a e9 [2] 4d f8 [2] 03 f4 [2] 0f fe [2] 18 f5 [2] 03 bb [2] 3e }

  condition:
    any of them
}