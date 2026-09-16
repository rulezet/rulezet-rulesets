rule TTP_XOR_MULT_DOSStub_8d6a {
  strings:
    $key_8d6a = { d9 02 [2] ad 1a [2] ea 18 [2] ad 09 [2] e3 05 [2] ef 0f [2] f8 04 [2] e3 4a [2] de }

  condition:
    any of them
}