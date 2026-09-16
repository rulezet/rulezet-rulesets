rule TTP_XOR_MULT_DOSStub_7a9b {
  strings:
    $key_7a9b = { 2e f3 [2] 5a eb [2] 1d e9 [2] 5a f8 [2] 14 f4 [2] 18 fe [2] 0f f5 [2] 14 bb [2] 29 }

  condition:
    any of them
}