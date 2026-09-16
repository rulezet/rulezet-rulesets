rule TTP_XOR_MULT_DOSStub_5ed4 {
  strings:
    $key_5ed4 = { 0a bc [2] 7e a4 [2] 39 a6 [2] 7e b7 [2] 30 bb [2] 3c b1 [2] 2b ba [2] 30 f4 [2] 0d }

  condition:
    any of them
}