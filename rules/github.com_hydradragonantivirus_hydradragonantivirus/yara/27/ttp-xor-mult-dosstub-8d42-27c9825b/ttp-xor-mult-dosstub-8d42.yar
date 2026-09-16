rule TTP_XOR_MULT_DOSStub_8d42 {
  strings:
    $key_8d42 = { d9 2a [2] ad 32 [2] ea 30 [2] ad 21 [2] e3 2d [2] ef 27 [2] f8 2c [2] e3 62 [2] de }

  condition:
    any of them
}