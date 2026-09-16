rule TTP_XOR_MULT_DOSStub_8dc1 {
  strings:
    $key_8dc1 = { d9 a9 [2] ad b1 [2] ea b3 [2] ad a2 [2] e3 ae [2] ef a4 [2] f8 af [2] e3 e1 [2] de }

  condition:
    any of them
}