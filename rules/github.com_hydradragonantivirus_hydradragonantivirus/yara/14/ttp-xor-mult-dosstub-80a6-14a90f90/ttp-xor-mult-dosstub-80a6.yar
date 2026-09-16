rule TTP_XOR_MULT_DOSStub_80a6 {
  strings:
    $key_80a6 = { d4 ce [2] a0 d6 [2] e7 d4 [2] a0 c5 [2] ee c9 [2] e2 c3 [2] f5 c8 [2] ee 86 [2] d3 }

  condition:
    any of them
}