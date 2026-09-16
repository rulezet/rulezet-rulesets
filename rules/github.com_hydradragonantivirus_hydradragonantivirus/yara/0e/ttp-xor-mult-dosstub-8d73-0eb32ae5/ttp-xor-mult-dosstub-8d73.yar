rule TTP_XOR_MULT_DOSStub_8d73 {
  strings:
    $key_8d73 = { d9 1b [2] ad 03 [2] ea 01 [2] ad 10 [2] e3 1c [2] ef 16 [2] f8 1d [2] e3 53 [2] de }

  condition:
    any of them
}