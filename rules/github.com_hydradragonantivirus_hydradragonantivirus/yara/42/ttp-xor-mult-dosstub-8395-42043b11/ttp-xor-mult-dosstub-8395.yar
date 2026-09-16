rule TTP_XOR_MULT_DOSStub_8395 {
  strings:
    $key_8395 = { d7 fd [2] a3 e5 [2] e4 e7 [2] a3 f6 [2] ed fa [2] e1 f0 [2] f6 fb [2] ed b5 [2] d0 }

  condition:
    any of them
}