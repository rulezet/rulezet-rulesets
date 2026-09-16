rule TTP_XOR_MULT_DOSStub_8d75 {
  strings:
    $key_8d75 = { d9 1d [2] ad 05 [2] ea 07 [2] ad 16 [2] e3 1a [2] ef 10 [2] f8 1b [2] e3 55 [2] de }

  condition:
    any of them
}