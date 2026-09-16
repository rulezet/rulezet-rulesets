rule TTP_XOR_MULT_DOSStub_8d7a {
  strings:
    $key_8d7a = { d9 12 [2] ad 0a [2] ea 08 [2] ad 19 [2] e3 15 [2] ef 1f [2] f8 14 [2] e3 5a [2] de }

  condition:
    any of them
}