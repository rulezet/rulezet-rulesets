rule TTP_XOR_MULT_DOSStub_5f9b {
  strings:
    $key_5f9b = { 0b f3 [2] 7f eb [2] 38 e9 [2] 7f f8 [2] 31 f4 [2] 3d fe [2] 2a f5 [2] 31 bb [2] 0c }

  condition:
    any of them
}