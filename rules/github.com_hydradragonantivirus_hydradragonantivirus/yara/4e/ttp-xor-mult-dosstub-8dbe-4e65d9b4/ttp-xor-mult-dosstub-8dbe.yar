rule TTP_XOR_MULT_DOSStub_8dbe {
  strings:
    $key_8dbe = { d9 d6 [2] ad ce [2] ea cc [2] ad dd [2] e3 d1 [2] ef db [2] f8 d0 [2] e3 9e [2] de }

  condition:
    any of them
}