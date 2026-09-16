rule TTP_XOR_MULT_DOSStub_7896 {
  strings:
    $key_7896 = { 2c fe [2] 58 e6 [2] 1f e4 [2] 58 f5 [2] 16 f9 [2] 1a f3 [2] 0d f8 [2] 16 b6 [2] 2b }

  condition:
    any of them
}