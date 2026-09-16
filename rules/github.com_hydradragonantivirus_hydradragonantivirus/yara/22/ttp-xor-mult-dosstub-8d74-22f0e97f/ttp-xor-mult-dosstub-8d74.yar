rule TTP_XOR_MULT_DOSStub_8d74 {
  strings:
    $key_8d74 = { d9 1c [2] ad 04 [2] ea 06 [2] ad 17 [2] e3 1b [2] ef 11 [2] f8 1a [2] e3 54 [2] de }

  condition:
    any of them
}