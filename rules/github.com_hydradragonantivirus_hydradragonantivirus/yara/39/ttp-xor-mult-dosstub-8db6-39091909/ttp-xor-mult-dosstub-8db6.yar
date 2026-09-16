rule TTP_XOR_MULT_DOSStub_8db6 {
  strings:
    $key_8db6 = { d9 de [2] ad c6 [2] ea c4 [2] ad d5 [2] e3 d9 [2] ef d3 [2] f8 d8 [2] e3 96 [2] de }

  condition:
    any of them
}