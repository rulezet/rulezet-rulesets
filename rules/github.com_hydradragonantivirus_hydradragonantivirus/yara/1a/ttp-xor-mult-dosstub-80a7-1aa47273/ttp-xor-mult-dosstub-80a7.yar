rule TTP_XOR_MULT_DOSStub_80a7 {
  strings:
    $key_80a7 = { d4 cf [2] a0 d7 [2] e7 d5 [2] a0 c4 [2] ee c8 [2] e2 c2 [2] f5 c9 [2] ee 87 [2] d3 }

  condition:
    any of them
}