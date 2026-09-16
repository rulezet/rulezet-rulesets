rule TTP_XOR_MULT_DOSStub_8dcb {
  strings:
    $key_8dcb = { d9 a3 [2] ad bb [2] ea b9 [2] ad a8 [2] e3 a4 [2] ef ae [2] f8 a5 [2] e3 eb [2] de }

  condition:
    any of them
}