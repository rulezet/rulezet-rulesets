rule TTP_XOR_MULT_DOSStub_b398 {
  strings:
    $key_b398 = { e7 f0 [2] 93 e8 [2] d4 ea [2] 93 fb [2] dd f7 [2] d1 fd [2] c6 f6 [2] dd b8 [2] e0 }

  condition:
    any of them
}