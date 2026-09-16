rule TTP_XOR_MULT_DOSStub_80a1 {
  strings:
    $key_80a1 = { d4 c9 [2] a0 d1 [2] e7 d3 [2] a0 c2 [2] ee ce [2] e2 c4 [2] f5 cf [2] ee 81 [2] d3 }

  condition:
    any of them
}