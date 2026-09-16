rule TTP_XOR_MULT_DOSStub_8d25 {
  strings:
    $key_8d25 = { d9 4d [2] ad 55 [2] ea 57 [2] ad 46 [2] e3 4a [2] ef 40 [2] f8 4b [2] e3 05 [2] de }

  condition:
    any of them
}