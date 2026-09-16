rule TTP_XOR_MULT_DOSStub_42dd {
  strings:
    $key_42dd = { 16 b5 [2] 62 ad [2] 25 af [2] 62 be [2] 2c b2 [2] 20 b8 [2] 37 b3 [2] 2c fd [2] 11 }

  condition:
    any of them
}