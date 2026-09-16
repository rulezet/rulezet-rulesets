rule TTP_XOR_MULT_DOSStub_1b9b {
  strings:
    $key_1b9b = { 4f f3 [2] 3b eb [2] 7c e9 [2] 3b f8 [2] 75 f4 [2] 79 fe [2] 6e f5 [2] 75 bb [2] 48 }

  condition:
    any of them
}