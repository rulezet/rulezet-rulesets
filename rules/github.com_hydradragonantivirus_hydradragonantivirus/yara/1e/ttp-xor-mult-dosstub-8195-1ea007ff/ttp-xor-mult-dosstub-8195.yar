rule TTP_XOR_MULT_DOSStub_8195 {
  strings:
    $key_8195 = { d5 fd [2] a1 e5 [2] e6 e7 [2] a1 f6 [2] ef fa [2] e3 f0 [2] f4 fb [2] ef b5 [2] d2 }

  condition:
    any of them
}