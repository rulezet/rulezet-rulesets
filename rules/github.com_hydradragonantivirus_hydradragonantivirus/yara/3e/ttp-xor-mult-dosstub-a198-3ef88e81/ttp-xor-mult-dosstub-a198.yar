rule TTP_XOR_MULT_DOSStub_a198 {
  strings:
    $key_a198 = { f5 f0 [2] 81 e8 [2] c6 ea [2] 81 fb [2] cf f7 [2] c3 fd [2] d4 f6 [2] cf b8 [2] f2 }

  condition:
    any of them
}