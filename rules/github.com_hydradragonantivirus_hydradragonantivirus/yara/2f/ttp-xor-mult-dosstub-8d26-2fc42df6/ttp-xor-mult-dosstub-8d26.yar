rule TTP_XOR_MULT_DOSStub_8d26 {
  strings:
    $key_8d26 = { d9 4e [2] ad 56 [2] ea 54 [2] ad 45 [2] e3 49 [2] ef 43 [2] f8 48 [2] e3 06 [2] de }

  condition:
    any of them
}