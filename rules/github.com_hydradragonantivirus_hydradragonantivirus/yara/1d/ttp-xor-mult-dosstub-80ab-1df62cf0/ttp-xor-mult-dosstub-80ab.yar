rule TTP_XOR_MULT_DOSStub_80ab {
  strings:
    $key_80ab = { d4 c3 [2] a0 db [2] e7 d9 [2] a0 c8 [2] ee c4 [2] e2 ce [2] f5 c5 [2] ee 8b [2] d3 }

  condition:
    any of them
}