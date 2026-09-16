rule TTP_XOR_MULT_DOSStub_8d6f {
  strings:
    $key_8d6f = { d9 07 [2] ad 1f [2] ea 1d [2] ad 0c [2] e3 00 [2] ef 0a [2] f8 01 [2] e3 4f [2] de }

  condition:
    any of them
}