rule TTP_XOR_MULT_DOSStub_7fc6 {
  strings:
    $key_7fc6 = { 2b ae [2] 5f b6 [2] 18 b4 [2] 5f a5 [2] 11 a9 [2] 1d a3 [2] 0a a8 [2] 11 e6 [2] 2c }

  condition:
    any of them
}