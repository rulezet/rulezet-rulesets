rule TTP_XOR_MULT_DOSStub_7f96 {
  strings:
    $key_7f96 = { 2b fe [2] 5f e6 [2] 18 e4 [2] 5f f5 [2] 11 f9 [2] 1d f3 [2] 0a f8 [2] 11 b6 [2] 2c }

  condition:
    any of them
}