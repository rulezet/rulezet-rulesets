rule TTP_XOR_MULT_DOSStub_6896 {
  strings:
    $key_6896 = { 3c fe [2] 48 e6 [2] 0f e4 [2] 48 f5 [2] 06 f9 [2] 0a f3 [2] 1d f8 [2] 06 b6 [2] 3b }

  condition:
    any of them
}