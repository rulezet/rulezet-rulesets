rule TTP_XOR_MULT_DOSStub_8d4e {
  strings:
    $key_8d4e = { d9 26 [2] ad 3e [2] ea 3c [2] ad 2d [2] e3 21 [2] ef 2b [2] f8 20 [2] e3 6e [2] de }

  condition:
    any of them
}