rule TTP_XOR_MULT_DOSStub_80b9 {
  strings:
    $key_80b9 = { d4 d1 [2] a0 c9 [2] e7 cb [2] a0 da [2] ee d6 [2] e2 dc [2] f5 d7 [2] ee 99 [2] d3 }

  condition:
    any of them
}