rule TTP_XOR_MULT_DOSStub_a593 {
  strings:
    $key_a593 = { f1 fb [2] 85 e3 [2] c2 e1 [2] 85 f0 [2] cb fc [2] c7 f6 [2] d0 fd [2] cb b3 [2] f6 }

  condition:
    any of them
}