rule TTP_XOR_MULT_DOSStub_0cc9 {
  strings:
    $key_0cc9 = { 58 a1 [2] 2c b9 [2] 6b bb [2] 2c aa [2] 62 a6 [2] 6e ac [2] 79 a7 [2] 62 e9 [2] 5f }

  condition:
    any of them
}