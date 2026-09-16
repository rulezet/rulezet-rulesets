rule TTP_XOR_MULT_DOSStub_a695 {
  strings:
    $key_a695 = { f2 fd [2] 86 e5 [2] c1 e7 [2] 86 f6 [2] c8 fa [2] c4 f0 [2] d3 fb [2] c8 b5 [2] f5 }

  condition:
    any of them
}