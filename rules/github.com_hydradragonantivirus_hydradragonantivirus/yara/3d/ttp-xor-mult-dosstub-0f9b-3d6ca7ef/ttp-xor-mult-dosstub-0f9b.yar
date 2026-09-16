rule TTP_XOR_MULT_DOSStub_0f9b {
  strings:
    $key_0f9b = { 5b f3 [2] 2f eb [2] 68 e9 [2] 2f f8 [2] 61 f4 [2] 6d fe [2] 7a f5 [2] 61 bb [2] 5c }

  condition:
    any of them
}