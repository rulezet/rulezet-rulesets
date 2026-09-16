rule TTP_XOR_MULT_DOSStub_8d44 {
  strings:
    $key_8d44 = { d9 2c [2] ad 34 [2] ea 36 [2] ad 27 [2] e3 2b [2] ef 21 [2] f8 2a [2] e3 64 [2] de }

  condition:
    any of them
}