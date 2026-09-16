rule TTP_XOR_MULT_DOSStub_bdc8 {
  strings:
    $key_bdc8 = { e9 a0 [2] 9d b8 [2] da ba [2] 9d ab [2] d3 a7 [2] df ad [2] c8 a6 [2] d3 e8 [2] ee }

  condition:
    any of them
}