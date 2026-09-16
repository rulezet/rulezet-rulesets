rule TTP_XOR_MULT_DOSStub_8dc0 {
  strings:
    $key_8dc0 = { d9 a8 [2] ad b0 [2] ea b2 [2] ad a3 [2] e3 af [2] ef a5 [2] f8 ae [2] e3 e0 [2] de }

  condition:
    any of them
}