rule TTP_XOR_MULT_DOSStub_8d2f {
  strings:
    $key_8d2f = { d9 47 [2] ad 5f [2] ea 5d [2] ad 4c [2] e3 40 [2] ef 4a [2] f8 41 [2] e3 0f [2] de }

  condition:
    any of them
}