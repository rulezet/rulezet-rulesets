rule TTP_XOR_MULT_DOSStub_bdc5 {
  strings:
    $key_bdc5 = { e9 ad [2] 9d b5 [2] da b7 [2] 9d a6 [2] d3 aa [2] df a0 [2] c8 ab [2] d3 e5 [2] ee }

  condition:
    any of them
}