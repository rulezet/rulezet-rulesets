rule TTP_XOR_MULT_DOSStub_8dab {
  strings:
    $key_8dab = { d9 c3 [2] ad db [2] ea d9 [2] ad c8 [2] e3 c4 [2] ef ce [2] f8 c5 [2] e3 8b [2] de }

  condition:
    any of them
}