rule TTP_XOR_MULT_DOSStub_8dc4 {
  strings:
    $key_8dc4 = { d9 ac [2] ad b4 [2] ea b6 [2] ad a7 [2] e3 ab [2] ef a1 [2] f8 aa [2] e3 e4 [2] de }

  condition:
    any of them
}