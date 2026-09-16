rule TTP_XOR_MULT_DOSStub_bdc0 {
  strings:
    $key_bdc0 = { e9 a8 [2] 9d b0 [2] da b2 [2] 9d a3 [2] d3 af [2] df a5 [2] c8 ae [2] d3 e0 [2] ee }

  condition:
    any of them
}