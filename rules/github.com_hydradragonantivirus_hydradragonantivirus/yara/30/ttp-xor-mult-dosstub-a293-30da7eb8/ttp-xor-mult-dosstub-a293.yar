rule TTP_XOR_MULT_DOSStub_a293 {
  strings:
    $key_a293 = { f6 fb [2] 82 e3 [2] c5 e1 [2] 82 f0 [2] cc fc [2] c0 f6 [2] d7 fd [2] cc b3 [2] f1 }

  condition:
    any of them
}