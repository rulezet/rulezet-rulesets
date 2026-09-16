rule TTP_XOR_MULT_DOSStub_8d4d {
  strings:
    $key_8d4d = { d9 25 [2] ad 3d [2] ea 3f [2] ad 2e [2] e3 22 [2] ef 28 [2] f8 23 [2] e3 6d [2] de }

  condition:
    any of them
}