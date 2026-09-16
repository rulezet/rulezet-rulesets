rule TTP_XOR_MULT_DOSStub_8495 {
  strings:
    $key_8495 = { d0 fd [2] a4 e5 [2] e3 e7 [2] a4 f6 [2] ea fa [2] e6 f0 [2] f1 fb [2] ea b5 [2] d7 }

  condition:
    any of them
}