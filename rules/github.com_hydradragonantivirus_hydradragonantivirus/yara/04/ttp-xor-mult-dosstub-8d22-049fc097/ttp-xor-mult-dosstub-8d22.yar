rule TTP_XOR_MULT_DOSStub_8d22 {
  strings:
    $key_8d22 = { d9 4a [2] ad 52 [2] ea 50 [2] ad 41 [2] e3 4d [2] ef 47 [2] f8 4c [2] e3 02 [2] de }

  condition:
    any of them
}