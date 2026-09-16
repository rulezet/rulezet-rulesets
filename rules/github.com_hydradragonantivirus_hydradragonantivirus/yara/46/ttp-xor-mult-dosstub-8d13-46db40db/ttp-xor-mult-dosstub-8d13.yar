rule TTP_XOR_MULT_DOSStub_8d13 {
  strings:
    $key_8d13 = { d9 7b [2] ad 63 [2] ea 61 [2] ad 70 [2] e3 7c [2] ef 76 [2] f8 7d [2] e3 33 [2] de }

  condition:
    any of them
}