rule TTP_XOR_MULT_DOSStub_6398 {
  strings:
    $key_6398 = { 37 f0 [2] 43 e8 [2] 04 ea [2] 43 fb [2] 0d f7 [2] 01 fd [2] 16 f6 [2] 0d b8 [2] 30 }

  condition:
    any of them
}