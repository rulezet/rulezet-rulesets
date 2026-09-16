rule TTP_XOR_MULT_DOSStub_a493 {
  strings:
    $key_a493 = { f0 fb [2] 84 e3 [2] c3 e1 [2] 84 f0 [2] ca fc [2] c6 f6 [2] d1 fd [2] ca b3 [2] f7 }

  condition:
    any of them
}