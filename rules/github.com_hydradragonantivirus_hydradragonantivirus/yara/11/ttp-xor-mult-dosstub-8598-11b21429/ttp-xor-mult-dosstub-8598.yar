rule TTP_XOR_MULT_DOSStub_8598 {
  strings:
    $key_8598 = { d1 f0 [2] a5 e8 [2] e2 ea [2] a5 fb [2] eb f7 [2] e7 fd [2] f0 f6 [2] eb b8 [2] d6 }

  condition:
    any of them
}