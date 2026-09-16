rule TTP_XOR_MULT_DOSStub_8193 {
  strings:
    $key_8193 = { d5 fb [2] a1 e3 [2] e6 e1 [2] a1 f0 [2] ef fc [2] e3 f6 [2] f4 fd [2] ef b3 [2] d2 }

  condition:
    any of them
}