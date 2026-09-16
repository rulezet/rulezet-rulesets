rule TTP_XOR_MULT_DOSStub_0cc2 {
  strings:
    $key_0cc2 = { 58 aa [2] 2c b2 [2] 6b b0 [2] 2c a1 [2] 62 ad [2] 6e a7 [2] 79 ac [2] 62 e2 [2] 5f }

  condition:
    any of them
}