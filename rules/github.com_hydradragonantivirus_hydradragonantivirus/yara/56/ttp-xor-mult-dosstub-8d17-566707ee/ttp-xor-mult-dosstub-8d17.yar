rule TTP_XOR_MULT_DOSStub_8d17 {
  strings:
    $key_8d17 = { d9 7f [2] ad 67 [2] ea 65 [2] ad 74 [2] e3 78 [2] ef 72 [2] f8 79 [2] e3 37 [2] de }

  condition:
    any of them
}