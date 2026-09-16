rule TTP_XOR_MULT_DOSStub_8d34 {
  strings:
    $key_8d34 = { d9 5c [2] ad 44 [2] ea 46 [2] ad 57 [2] e3 5b [2] ef 51 [2] f8 5a [2] e3 14 [2] de }

  condition:
    any of them
}