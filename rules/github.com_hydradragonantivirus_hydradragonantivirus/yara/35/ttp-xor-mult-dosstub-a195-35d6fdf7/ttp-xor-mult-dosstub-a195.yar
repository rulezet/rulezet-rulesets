rule TTP_XOR_MULT_DOSStub_a195 {
  strings:
    $key_a195 = { f5 fd [2] 81 e5 [2] c6 e7 [2] 81 f6 [2] cf fa [2] c3 f0 [2] d4 fb [2] cf b5 [2] f2 }

  condition:
    any of them
}