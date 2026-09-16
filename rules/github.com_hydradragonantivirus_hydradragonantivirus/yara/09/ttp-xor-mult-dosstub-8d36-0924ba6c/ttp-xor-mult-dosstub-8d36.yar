rule TTP_XOR_MULT_DOSStub_8d36 {
  strings:
    $key_8d36 = { d9 5e [2] ad 46 [2] ea 44 [2] ad 55 [2] e3 59 [2] ef 53 [2] f8 58 [2] e3 16 [2] de }

  condition:
    any of them
}