rule TTP_XOR_MULT_DOSStub_8d40 {
  strings:
    $key_8d40 = { d9 28 [2] ad 30 [2] ea 32 [2] ad 23 [2] e3 2f [2] ef 25 [2] f8 2e [2] e3 60 [2] de }

  condition:
    any of them
}