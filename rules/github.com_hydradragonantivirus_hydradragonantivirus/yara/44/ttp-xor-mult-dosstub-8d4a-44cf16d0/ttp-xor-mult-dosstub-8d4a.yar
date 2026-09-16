rule TTP_XOR_MULT_DOSStub_8d4a {
  strings:
    $key_8d4a = { d9 22 [2] ad 3a [2] ea 38 [2] ad 29 [2] e3 25 [2] ef 2f [2] f8 24 [2] e3 6a [2] de }

  condition:
    any of them
}