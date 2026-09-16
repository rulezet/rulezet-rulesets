rule TTP_XOR_MULT_DOSStub_8dd9 {
  strings:
    $key_8dd9 = { d9 b1 [2] ad a9 [2] ea ab [2] ad ba [2] e3 b6 [2] ef bc [2] f8 b7 [2] e3 f9 [2] de }

  condition:
    any of them
}