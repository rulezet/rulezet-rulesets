rule TTP_XOR_MULT_DOSStub_4298 {
  strings:
    $key_4298 = { 16 f0 [2] 62 e8 [2] 25 ea [2] 62 fb [2] 2c f7 [2] 20 fd [2] 37 f6 [2] 2c b8 [2] 11 }

  condition:
    any of them
}