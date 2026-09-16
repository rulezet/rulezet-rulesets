rule TTP_XOR_MULT_DOSStub_78d7 {
  strings:
    $key_78d7 = { 2c bf [2] 58 a7 [2] 1f a5 [2] 58 b4 [2] 16 b8 [2] 1a b2 [2] 0d b9 [2] 16 f7 [2] 2b }

  condition:
    any of them
}