rule TTP_XOR_MULT_DOSStub_8db5 {
  strings:
    $key_8db5 = { d9 dd [2] ad c5 [2] ea c7 [2] ad d6 [2] e3 da [2] ef d0 [2] f8 db [2] e3 95 [2] de }

  condition:
    any of them
}