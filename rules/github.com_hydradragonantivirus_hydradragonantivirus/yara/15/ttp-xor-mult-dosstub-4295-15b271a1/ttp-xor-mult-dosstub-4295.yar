rule TTP_XOR_MULT_DOSStub_4295 {
  strings:
    $key_4295 = { 16 fd [2] 62 e5 [2] 25 e7 [2] 62 f6 [2] 2c fa [2] 20 f0 [2] 37 fb [2] 2c b5 [2] 11 }

  condition:
    any of them
}