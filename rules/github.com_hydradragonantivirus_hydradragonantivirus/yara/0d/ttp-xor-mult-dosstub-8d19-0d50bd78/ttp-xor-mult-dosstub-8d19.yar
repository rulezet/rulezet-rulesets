rule TTP_XOR_MULT_DOSStub_8d19 {
  strings:
    $key_8d19 = { d9 71 [2] ad 69 [2] ea 6b [2] ad 7a [2] e3 76 [2] ef 7c [2] f8 77 [2] e3 39 [2] de }

  condition:
    any of them
}