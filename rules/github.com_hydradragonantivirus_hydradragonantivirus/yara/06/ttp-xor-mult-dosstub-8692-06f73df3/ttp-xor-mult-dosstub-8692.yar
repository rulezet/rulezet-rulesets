rule TTP_XOR_MULT_DOSStub_8692 {
  strings:
    $key_8692 = { d2 fa [2] a6 e2 [2] e1 e0 [2] a6 f1 [2] e8 fd [2] e4 f7 [2] f3 fc [2] e8 b2 [2] d5 }

  condition:
    any of them
}