rule TTP_XOR_MULT_DOSStub_8db3 {
  strings:
    $key_8db3 = { d9 db [2] ad c3 [2] ea c1 [2] ad d0 [2] e3 dc [2] ef d6 [2] f8 dd [2] e3 93 [2] de }

  condition:
    any of them
}