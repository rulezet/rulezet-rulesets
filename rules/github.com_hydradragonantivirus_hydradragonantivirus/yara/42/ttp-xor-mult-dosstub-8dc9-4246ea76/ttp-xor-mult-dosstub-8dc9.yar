rule TTP_XOR_MULT_DOSStub_8dc9 {
  strings:
    $key_8dc9 = { d9 a1 [2] ad b9 [2] ea bb [2] ad aa [2] e3 a6 [2] ef ac [2] f8 a7 [2] e3 e9 [2] de }

  condition:
    any of them
}