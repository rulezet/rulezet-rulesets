rule TTP_XOR_MULT_DOSStub_0cc1 {
  strings:
    $key_0cc1 = { 58 a9 [2] 2c b1 [2] 6b b3 [2] 2c a2 [2] 62 ae [2] 6e a4 [2] 79 af [2] 62 e1 [2] 5f }

  condition:
    any of them
}