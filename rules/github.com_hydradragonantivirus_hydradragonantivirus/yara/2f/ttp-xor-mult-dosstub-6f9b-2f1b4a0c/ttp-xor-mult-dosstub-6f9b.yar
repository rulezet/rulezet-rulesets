rule TTP_XOR_MULT_DOSStub_6f9b {
  strings:
    $key_6f9b = { 3b f3 [2] 4f eb [2] 08 e9 [2] 4f f8 [2] 01 f4 [2] 0d fe [2] 1a f5 [2] 01 bb [2] 3c }

  condition:
    any of them
}