rule TTP_XOR_MULT_DOSStub_0896 {
  strings:
    $key_0896 = { 5c fe [2] 28 e6 [2] 6f e4 [2] 28 f5 [2] 66 f9 [2] 6a f3 [2] 7d f8 [2] 66 b6 [2] 5b }

  condition:
    any of them
}