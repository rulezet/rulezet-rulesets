rule TTP_XOR_MULT_DOSStub_8d43 {
  strings:
    $key_8d43 = { d9 2b [2] ad 33 [2] ea 31 [2] ad 20 [2] e3 2c [2] ef 26 [2] f8 2d [2] e3 63 [2] de }

  condition:
    any of them
}