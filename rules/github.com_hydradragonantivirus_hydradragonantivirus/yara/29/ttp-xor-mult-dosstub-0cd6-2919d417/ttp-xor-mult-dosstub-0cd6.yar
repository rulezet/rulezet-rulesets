rule TTP_XOR_MULT_DOSStub_0cd6 {
  strings:
    $key_0cd6 = { 58 be [2] 2c a6 [2] 6b a4 [2] 2c b5 [2] 62 b9 [2] 6e b3 [2] 79 b8 [2] 62 f6 [2] 5f }

  condition:
    any of them
}