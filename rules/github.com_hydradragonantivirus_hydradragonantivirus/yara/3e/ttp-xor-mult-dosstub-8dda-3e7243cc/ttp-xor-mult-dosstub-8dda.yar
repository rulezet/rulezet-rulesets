rule TTP_XOR_MULT_DOSStub_8dda {
  strings:
    $key_8dda = { d9 b2 [2] ad aa [2] ea a8 [2] ad b9 [2] e3 b5 [2] ef bf [2] f8 b4 [2] e3 fa [2] de }

  condition:
    any of them
}