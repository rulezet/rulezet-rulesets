rule TTP_XOR_MULT_DOSStub_0cc3 {
  strings:
    $key_0cc3 = { 58 ab [2] 2c b3 [2] 6b b1 [2] 2c a0 [2] 62 ac [2] 6e a6 [2] 79 ad [2] 62 e3 [2] 5f }

  condition:
    any of them
}