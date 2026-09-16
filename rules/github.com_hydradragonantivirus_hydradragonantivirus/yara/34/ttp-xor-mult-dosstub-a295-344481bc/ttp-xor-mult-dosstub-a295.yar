rule TTP_XOR_MULT_DOSStub_a295 {
  strings:
    $key_a295 = { f6 fd [2] 82 e5 [2] c5 e7 [2] 82 f6 [2] cc fa [2] c0 f0 [2] d7 fb [2] cc b5 [2] f1 }

  condition:
    any of them
}