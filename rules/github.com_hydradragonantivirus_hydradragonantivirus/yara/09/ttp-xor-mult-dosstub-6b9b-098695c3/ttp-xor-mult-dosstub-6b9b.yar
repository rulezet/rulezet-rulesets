rule TTP_XOR_MULT_DOSStub_6b9b {
  strings:
    $key_6b9b = { 3f f3 [2] 4b eb [2] 0c e9 [2] 4b f8 [2] 05 f4 [2] 09 fe [2] 1e f5 [2] 05 bb [2] 38 }

  condition:
    any of them
}