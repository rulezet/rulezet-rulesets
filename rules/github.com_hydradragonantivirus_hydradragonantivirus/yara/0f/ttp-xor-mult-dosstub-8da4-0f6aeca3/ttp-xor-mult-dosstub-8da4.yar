rule TTP_XOR_MULT_DOSStub_8da4 {
  strings:
    $key_8da4 = { d9 cc [2] ad d4 [2] ea d6 [2] ad c7 [2] e3 cb [2] ef c1 [2] f8 ca [2] e3 84 [2] de }

  condition:
    any of them
}