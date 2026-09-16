rule TTP_XOR_MULT_DOSStub_4398 {
  strings:
    $key_4398 = { 17 f0 [2] 63 e8 [2] 24 ea [2] 63 fb [2] 2d f7 [2] 21 fd [2] 36 f6 [2] 2d b8 [2] 10 }

  condition:
    any of them
}