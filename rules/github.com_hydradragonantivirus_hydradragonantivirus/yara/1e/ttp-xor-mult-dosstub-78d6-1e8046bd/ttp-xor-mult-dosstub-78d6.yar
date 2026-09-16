rule TTP_XOR_MULT_DOSStub_78d6 {
  strings:
    $key_78d6 = { 2c be [2] 58 a6 [2] 1f a4 [2] 58 b5 [2] 16 b9 [2] 1a b3 [2] 0d b8 [2] 16 f6 [2] 2b }

  condition:
    any of them
}