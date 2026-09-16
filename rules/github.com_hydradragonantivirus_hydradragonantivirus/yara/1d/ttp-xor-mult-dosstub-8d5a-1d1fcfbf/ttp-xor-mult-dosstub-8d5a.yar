rule TTP_XOR_MULT_DOSStub_8d5a {
  strings:
    $key_8d5a = { d9 32 [2] ad 2a [2] ea 28 [2] ad 39 [2] e3 35 [2] ef 3f [2] f8 34 [2] e3 7a [2] de }

  condition:
    any of them
}