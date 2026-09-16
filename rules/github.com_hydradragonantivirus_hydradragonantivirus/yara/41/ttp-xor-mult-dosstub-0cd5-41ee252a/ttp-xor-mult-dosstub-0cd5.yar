rule TTP_XOR_MULT_DOSStub_0cd5 {
  strings:
    $key_0cd5 = { 58 bd [2] 2c a5 [2] 6b a7 [2] 2c b6 [2] 62 ba [2] 6e b0 [2] 79 bb [2] 62 f5 [2] 5f }

  condition:
    any of them
}