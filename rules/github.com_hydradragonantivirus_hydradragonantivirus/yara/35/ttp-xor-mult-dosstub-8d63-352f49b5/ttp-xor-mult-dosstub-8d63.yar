rule TTP_XOR_MULT_DOSStub_8d63 {
  strings:
    $key_8d63 = { d9 0b [2] ad 13 [2] ea 11 [2] ad 00 [2] e3 0c [2] ef 06 [2] f8 0d [2] e3 43 [2] de }

  condition:
    any of them
}