rule TTP_XOR_MULT_DOSStub_8d50 {
  strings:
    $key_8d50 = { d9 38 [2] ad 20 [2] ea 22 [2] ad 33 [2] e3 3f [2] ef 35 [2] f8 3e [2] e3 70 [2] de }

  condition:
    any of them
}