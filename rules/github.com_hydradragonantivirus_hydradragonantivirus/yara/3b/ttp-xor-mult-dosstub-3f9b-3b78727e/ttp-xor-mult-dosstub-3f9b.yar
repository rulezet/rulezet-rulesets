rule TTP_XOR_MULT_DOSStub_3f9b {
  strings:
    $key_3f9b = { 6b f3 [2] 1f eb [2] 58 e9 [2] 1f f8 [2] 51 f4 [2] 5d fe [2] 4a f5 [2] 51 bb [2] 6c }

  condition:
    any of them
}