rule TTP_XOR_MULT_DOSStub_4b9b {
  strings:
    $key_4b9b = { 1f f3 [2] 6b eb [2] 2c e9 [2] 6b f8 [2] 25 f4 [2] 29 fe [2] 3e f5 [2] 25 bb [2] 18 }

  condition:
    any of them
}