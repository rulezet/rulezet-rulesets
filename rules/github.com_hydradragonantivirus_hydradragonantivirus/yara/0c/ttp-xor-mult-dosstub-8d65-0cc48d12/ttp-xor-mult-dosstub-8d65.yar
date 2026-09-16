rule TTP_XOR_MULT_DOSStub_8d65 {
  strings:
    $key_8d65 = { d9 0d [2] ad 15 [2] ea 17 [2] ad 06 [2] e3 0a [2] ef 00 [2] f8 0b [2] e3 45 [2] de }

  condition:
    any of them
}