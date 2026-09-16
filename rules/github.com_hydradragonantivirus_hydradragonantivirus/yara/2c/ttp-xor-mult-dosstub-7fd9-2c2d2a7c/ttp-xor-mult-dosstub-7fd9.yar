rule TTP_XOR_MULT_DOSStub_7fd9 {
  strings:
    $key_7fd9 = { 2b b1 [2] 5f a9 [2] 18 ab [2] 5f ba [2] 11 b6 [2] 1d bc [2] 0a b7 [2] 11 f9 [2] 2c }

  condition:
    any of them
}