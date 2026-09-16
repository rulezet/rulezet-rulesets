rule TTP_XOR_MULT_DOSStub_80a4 {
  strings:
    $key_80a4 = { d4 cc [2] a0 d4 [2] e7 d6 [2] a0 c7 [2] ee cb [2] e2 c1 [2] f5 ca [2] ee 84 [2] d3 }

  condition:
    any of them
}