rule TTP_XOR_MULT_DOSStub_8da6 {
  strings:
    $key_8da6 = { d9 ce [2] ad d6 [2] ea d4 [2] ad c5 [2] e3 c9 [2] ef c3 [2] f8 c8 [2] e3 86 [2] de }

  condition:
    any of them
}