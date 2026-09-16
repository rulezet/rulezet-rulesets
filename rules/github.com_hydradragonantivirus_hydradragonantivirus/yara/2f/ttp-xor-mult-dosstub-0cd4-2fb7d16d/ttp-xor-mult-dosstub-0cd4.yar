rule TTP_XOR_MULT_DOSStub_0cd4 {
  strings:
    $key_0cd4 = { 58 bc [2] 2c a4 [2] 6b a6 [2] 2c b7 [2] 62 bb [2] 6e b1 [2] 79 ba [2] 62 f4 [2] 5f }

  condition:
    any of them
}