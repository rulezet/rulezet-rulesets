rule TTP_XOR_MULT_DOSStub_3a9b {
  strings:
    $key_3a9b = { 6e f3 [2] 1a eb [2] 5d e9 [2] 1a f8 [2] 54 f4 [2] 58 fe [2] 4f f5 [2] 54 bb [2] 69 }

  condition:
    any of them
}