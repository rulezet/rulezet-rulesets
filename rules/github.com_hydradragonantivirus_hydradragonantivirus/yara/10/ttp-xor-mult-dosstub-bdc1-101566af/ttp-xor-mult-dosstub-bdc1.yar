rule TTP_XOR_MULT_DOSStub_bdc1 {
  strings:
    $key_bdc1 = { e9 a9 [2] 9d b1 [2] da b3 [2] 9d a2 [2] d3 ae [2] df a4 [2] c8 af [2] d3 e1 [2] ee }

  condition:
    any of them
}