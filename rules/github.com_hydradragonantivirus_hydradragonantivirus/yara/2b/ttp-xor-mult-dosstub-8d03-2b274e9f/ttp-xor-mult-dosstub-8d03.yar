rule TTP_XOR_MULT_DOSStub_8d03 {
  strings:
    $key_8d03 = { d9 6b [2] ad 73 [2] ea 71 [2] ad 60 [2] e3 6c [2] ef 66 [2] f8 6d [2] e3 23 [2] de }

  condition:
    any of them
}