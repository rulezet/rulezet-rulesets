rule TTP_XOR_MULT_DOSStub_7fd6 {
  strings:
    $key_7fd6 = { 2b be [2] 5f a6 [2] 18 a4 [2] 5f b5 [2] 11 b9 [2] 1d b3 [2] 0a b8 [2] 11 f6 [2] 2c }

  condition:
    any of them
}