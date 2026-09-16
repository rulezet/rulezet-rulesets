rule TTP_XOR_MULT_DOSStub_8698 {
  strings:
    $key_8698 = { d2 f0 [2] a6 e8 [2] e1 ea [2] a6 fb [2] e8 f7 [2] e4 fd [2] f3 f6 [2] e8 b8 [2] d5 }

  condition:
    any of them
}