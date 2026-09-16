rule TTP_XOR_MULT_DOSStub_5896 {
  strings:
    $key_5896 = { 0c fe [2] 78 e6 [2] 3f e4 [2] 78 f5 [2] 36 f9 [2] 3a f3 [2] 2d f8 [2] 36 b6 [2] 0b }

  condition:
    any of them
}