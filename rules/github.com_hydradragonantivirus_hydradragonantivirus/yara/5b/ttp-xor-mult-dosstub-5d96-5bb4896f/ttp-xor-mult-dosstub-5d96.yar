rule TTP_XOR_MULT_DOSStub_5d96 {
  strings:
    $key_5d96 = { 09 fe [2] 7d e6 [2] 3a e4 [2] 7d f5 [2] 33 f9 [2] 3f f3 [2] 28 f8 [2] 33 b6 [2] 0e }

  condition:
    any of them
}