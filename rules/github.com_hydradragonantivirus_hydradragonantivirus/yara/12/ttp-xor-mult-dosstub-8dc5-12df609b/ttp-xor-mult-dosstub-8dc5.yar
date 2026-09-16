rule TTP_XOR_MULT_DOSStub_8dc5 {
  strings:
    $key_8dc5 = { d9 ad [2] ad b5 [2] ea b7 [2] ad a6 [2] e3 aa [2] ef a0 [2] f8 ab [2] e3 e5 [2] de }

  condition:
    any of them
}