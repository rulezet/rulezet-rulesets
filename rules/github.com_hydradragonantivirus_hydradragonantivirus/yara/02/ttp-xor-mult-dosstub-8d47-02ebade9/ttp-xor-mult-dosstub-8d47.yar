rule TTP_XOR_MULT_DOSStub_8d47 {
  strings:
    $key_8d47 = { d9 2f [2] ad 37 [2] ea 35 [2] ad 24 [2] e3 28 [2] ef 22 [2] f8 29 [2] e3 67 [2] de }

  condition:
    any of them
}