rule TTP_XOR_MULT_DOSStub_6298 {
  strings:
    $key_6298 = { 36 f0 [2] 42 e8 [2] 05 ea [2] 42 fb [2] 0c f7 [2] 00 fd [2] 17 f6 [2] 0c b8 [2] 31 }

  condition:
    any of them
}