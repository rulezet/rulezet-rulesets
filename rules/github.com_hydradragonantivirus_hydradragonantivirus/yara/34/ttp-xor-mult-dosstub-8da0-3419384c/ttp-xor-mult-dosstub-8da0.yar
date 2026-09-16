rule TTP_XOR_MULT_DOSStub_8da0 {
  strings:
    $key_8da0 = { d9 c8 [2] ad d0 [2] ea d2 [2] ad c3 [2] e3 cf [2] ef c5 [2] f8 ce [2] e3 80 [2] de }

  condition:
    any of them
}