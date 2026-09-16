rule TTP_XOR_MULT_DOSStub_a298 {
  strings:
    $key_a298 = { f6 f0 [2] 82 e8 [2] c5 ea [2] 82 fb [2] cc f7 [2] c0 fd [2] d7 f6 [2] cc b8 [2] f1 }

  condition:
    any of them
}