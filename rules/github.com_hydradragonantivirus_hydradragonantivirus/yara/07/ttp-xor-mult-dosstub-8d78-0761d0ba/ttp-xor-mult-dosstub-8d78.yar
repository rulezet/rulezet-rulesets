rule TTP_XOR_MULT_DOSStub_8d78 {
  strings:
    $key_8d78 = { d9 10 [2] ad 08 [2] ea 0a [2] ad 1b [2] e3 17 [2] ef 1d [2] f8 16 [2] e3 58 [2] de }

  condition:
    any of them
}