rule TTP_XOR_MULT_DOSStub_4896 {
  strings:
    $key_4896 = { 1c fe [2] 68 e6 [2] 2f e4 [2] 68 f5 [2] 26 f9 [2] 2a f3 [2] 3d f8 [2] 26 b6 [2] 1b }

  condition:
    any of them
}