rule TTP_XOR_MULT_DOSStub_8d1f {
  strings:
    $key_8d1f = { d9 77 [2] ad 6f [2] ea 6d [2] ad 7c [2] e3 70 [2] ef 7a [2] f8 71 [2] e3 3f [2] de }

  condition:
    any of them
}