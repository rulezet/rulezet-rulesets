rule TTP_XOR_MULT_DOSStub_7498 {
  strings:
    $key_7498 = { 20 f0 [2] 54 e8 [2] 13 ea [2] 54 fb [2] 1a f7 [2] 16 fd [2] 01 f6 [2] 1a b8 [2] 27 }

  condition:
    any of them
}