rule TTP_XOR_MULT_DOSStub_1398 {
  strings:
    $key_1398 = { 47 f0 [2] 33 e8 [2] 74 ea [2] 33 fb [2] 7d f7 [2] 71 fd [2] 66 f6 [2] 7d b8 [2] 40 }

  condition:
    any of them
}