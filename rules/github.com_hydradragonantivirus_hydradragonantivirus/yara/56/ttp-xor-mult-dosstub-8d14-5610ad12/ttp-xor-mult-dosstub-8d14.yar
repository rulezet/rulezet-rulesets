rule TTP_XOR_MULT_DOSStub_8d14 {
  strings:
    $key_8d14 = { d9 7c [2] ad 64 [2] ea 66 [2] ad 77 [2] e3 7b [2] ef 71 [2] f8 7a [2] e3 34 [2] de }

  condition:
    any of them
}