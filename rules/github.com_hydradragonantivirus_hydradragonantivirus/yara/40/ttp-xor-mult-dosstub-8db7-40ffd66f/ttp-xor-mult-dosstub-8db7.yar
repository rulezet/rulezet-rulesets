rule TTP_XOR_MULT_DOSStub_8db7 {
  strings:
    $key_8db7 = { d9 df [2] ad c7 [2] ea c5 [2] ad d4 [2] e3 d8 [2] ef d2 [2] f8 d9 [2] e3 97 [2] de }

  condition:
    any of them
}