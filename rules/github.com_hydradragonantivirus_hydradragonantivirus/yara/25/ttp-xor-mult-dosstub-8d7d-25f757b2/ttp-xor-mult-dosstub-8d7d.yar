rule TTP_XOR_MULT_DOSStub_8d7d {
  strings:
    $key_8d7d = { d9 15 [2] ad 0d [2] ea 0f [2] ad 1e [2] e3 12 [2] ef 18 [2] f8 13 [2] e3 5d [2] de }

  condition:
    any of them
}