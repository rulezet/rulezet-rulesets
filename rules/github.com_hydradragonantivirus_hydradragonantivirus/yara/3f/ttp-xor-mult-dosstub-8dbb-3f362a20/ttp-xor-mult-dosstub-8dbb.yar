rule TTP_XOR_MULT_DOSStub_8dbb {
  strings:
    $key_8dbb = { d9 d3 [2] ad cb [2] ea c9 [2] ad d8 [2] e3 d4 [2] ef de [2] f8 d5 [2] e3 9b [2] de }

  condition:
    any of them
}