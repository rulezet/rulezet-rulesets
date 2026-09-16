rule TTP_XOR_MULT_DOSStub_4ed4 {
  strings:
    $key_4ed4 = { 1a bc [2] 6e a4 [2] 29 a6 [2] 6e b7 [2] 20 bb [2] 2c b1 [2] 3b ba [2] 20 f4 [2] 1d }

  condition:
    any of them
}