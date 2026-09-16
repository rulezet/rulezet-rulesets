rule TTP_XOR_MULT_DOSStub_a793 {
  strings:
    $key_a793 = { f3 fb [2] 87 e3 [2] c0 e1 [2] 87 f0 [2] c9 fc [2] c5 f6 [2] d2 fd [2] c9 b3 [2] f4 }

  condition:
    any of them
}