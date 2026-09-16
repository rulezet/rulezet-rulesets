rule TTP_XOR_MULT_DOSStub_2a9b {
  strings:
    $key_2a9b = { 7e f3 [2] 0a eb [2] 4d e9 [2] 0a f8 [2] 44 f4 [2] 48 fe [2] 5f f5 [2] 44 bb [2] 79 }

  condition:
    any of them
}