rule TTP_XOR_MULT_DOSStub_1896 {
  strings:
    $key_1896 = { 4c fe [2] 38 e6 [2] 7f e4 [2] 38 f5 [2] 76 f9 [2] 7a f3 [2] 6d f8 [2] 76 b6 [2] 4b }

  condition:
    any of them
}