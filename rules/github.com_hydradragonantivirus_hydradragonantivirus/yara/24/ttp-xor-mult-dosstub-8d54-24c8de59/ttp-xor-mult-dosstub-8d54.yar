rule TTP_XOR_MULT_DOSStub_8d54 {
  strings:
    $key_8d54 = { d9 3c [2] ad 24 [2] ea 26 [2] ad 37 [2] e3 3b [2] ef 31 [2] f8 3a [2] e3 74 [2] de }

  condition:
    any of them
}