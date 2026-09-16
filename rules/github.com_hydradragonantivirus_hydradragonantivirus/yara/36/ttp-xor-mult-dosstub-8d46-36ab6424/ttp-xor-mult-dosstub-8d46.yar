rule TTP_XOR_MULT_DOSStub_8d46 {
  strings:
    $key_8d46 = { d9 2e [2] ad 36 [2] ea 34 [2] ad 25 [2] e3 29 [2] ef 23 [2] f8 28 [2] e3 66 [2] de }

  condition:
    any of them
}