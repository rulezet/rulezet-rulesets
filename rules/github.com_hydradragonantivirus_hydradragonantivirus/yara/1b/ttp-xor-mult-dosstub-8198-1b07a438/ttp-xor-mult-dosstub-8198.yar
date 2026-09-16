rule TTP_XOR_MULT_DOSStub_8198 {
  strings:
    $key_8198 = { d5 f0 [2] a1 e8 [2] e6 ea [2] a1 fb [2] ef f7 [2] e3 fd [2] f4 f6 [2] ef b8 [2] d2 }

  condition:
    any of them
}