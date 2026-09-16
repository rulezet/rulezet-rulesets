rule TTP_XOR_MULT_DOSStub_8d56 {
  strings:
    $key_8d56 = { d9 3e [2] ad 26 [2] ea 24 [2] ad 35 [2] e3 39 [2] ef 33 [2] f8 38 [2] e3 76 [2] de }

  condition:
    any of them
}