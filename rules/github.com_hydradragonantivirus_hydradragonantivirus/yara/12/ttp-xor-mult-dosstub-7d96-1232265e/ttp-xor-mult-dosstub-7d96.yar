rule TTP_XOR_MULT_DOSStub_7d96 {
  strings:
    $key_7d96 = { 29 fe [2] 5d e6 [2] 1a e4 [2] 5d f5 [2] 13 f9 [2] 1f f3 [2] 08 f8 [2] 13 b6 [2] 2e }

  condition:
    any of them
}