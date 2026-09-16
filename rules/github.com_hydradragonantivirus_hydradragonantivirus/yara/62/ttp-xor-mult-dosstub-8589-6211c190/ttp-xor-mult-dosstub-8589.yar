rule TTP_XOR_MULT_DOSStub_8589 {
  strings:
    $key_8589 = { d1 e1 [2] a5 f9 [2] e2 fb [2] a5 ea [2] eb e6 [2] e7 ec [2] f0 e7 [2] eb a9 [2] d6 }

  condition:
    any of them
}