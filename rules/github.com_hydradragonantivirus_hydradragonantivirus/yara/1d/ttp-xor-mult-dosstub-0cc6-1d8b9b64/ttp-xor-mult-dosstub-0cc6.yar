rule TTP_XOR_MULT_DOSStub_0cc6 {
  strings:
    $key_0cc6 = { 58 ae [2] 2c b6 [2] 6b b4 [2] 2c a5 [2] 62 a9 [2] 6e a3 [2] 79 a8 [2] 62 e6 [2] 5f }

  condition:
    any of them
}