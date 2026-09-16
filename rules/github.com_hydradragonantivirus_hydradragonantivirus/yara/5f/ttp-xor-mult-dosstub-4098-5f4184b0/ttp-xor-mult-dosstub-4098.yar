rule TTP_XOR_MULT_DOSStub_4098 {
  strings:
    $key_4098 = { 14 f0 [2] 60 e8 [2] 27 ea [2] 60 fb [2] 2e f7 [2] 22 fd [2] 35 f6 [2] 2e b8 [2] 13 }

  condition:
    any of them
}