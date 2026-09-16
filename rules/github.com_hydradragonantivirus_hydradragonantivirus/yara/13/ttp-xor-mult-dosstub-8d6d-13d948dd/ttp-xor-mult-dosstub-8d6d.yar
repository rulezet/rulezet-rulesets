rule TTP_XOR_MULT_DOSStub_8d6d {
  strings:
    $key_8d6d = { d9 05 [2] ad 1d [2] ea 1f [2] ad 0e [2] e3 02 [2] ef 08 [2] f8 03 [2] e3 4d [2] de }

  condition:
    any of them
}