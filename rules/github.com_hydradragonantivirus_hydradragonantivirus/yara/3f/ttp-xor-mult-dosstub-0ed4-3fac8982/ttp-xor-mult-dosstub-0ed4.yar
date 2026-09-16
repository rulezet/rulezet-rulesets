rule TTP_XOR_MULT_DOSStub_0ed4 {
  strings:
    $key_0ed4 = { 5a bc [2] 2e a4 [2] 69 a6 [2] 2e b7 [2] 60 bb [2] 6c b1 [2] 7b ba [2] 60 f4 [2] 5d }

  condition:
    any of them
}