rule TTP_XOR_MULT_DOSStub_8d79 {
  strings:
    $key_8d79 = { d9 11 [2] ad 09 [2] ea 0b [2] ad 1a [2] e3 16 [2] ef 1c [2] f8 17 [2] e3 59 [2] de }

  condition:
    any of them
}