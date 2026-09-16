rule TTP_XOR_MULT_DOSStub_8d53 {
  strings:
    $key_8d53 = { d9 3b [2] ad 23 [2] ea 21 [2] ad 30 [2] e3 3c [2] ef 36 [2] f8 3d [2] e3 73 [2] de }

  condition:
    any of them
}