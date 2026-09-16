rule TTP_XOR_MULT_DOSStub_8d0a {
  strings:
    $key_8d0a = { d9 62 [2] ad 7a [2] ea 78 [2] ad 69 [2] e3 65 [2] ef 6f [2] f8 64 [2] e3 2a [2] de }

  condition:
    any of them
}