rule TTP_XOR_MULT_DOSStub_8d33 {
  strings:
    $key_8d33 = { d9 5b [2] ad 43 [2] ea 41 [2] ad 50 [2] e3 5c [2] ef 56 [2] f8 5d [2] e3 13 [2] de }

  condition:
    any of them
}