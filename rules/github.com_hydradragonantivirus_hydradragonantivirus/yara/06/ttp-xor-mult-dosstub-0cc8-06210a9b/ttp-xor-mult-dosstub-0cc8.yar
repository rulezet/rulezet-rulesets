rule TTP_XOR_MULT_DOSStub_0cc8 {
  strings:
    $key_0cc8 = { 58 a0 [2] 2c b8 [2] 6b ba [2] 2c ab [2] 62 a7 [2] 6e ad [2] 79 a6 [2] 62 e8 [2] 5f }

  condition:
    any of them
}