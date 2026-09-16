rule TTP_XOR_MULT_DOSStub_4f96 {
  strings:
    $key_4f96 = { 1b fe [2] 6f e6 [2] 28 e4 [2] 6f f5 [2] 21 f9 [2] 2d f3 [2] 3a f8 [2] 21 b6 [2] 1c }

  condition:
    any of them
}