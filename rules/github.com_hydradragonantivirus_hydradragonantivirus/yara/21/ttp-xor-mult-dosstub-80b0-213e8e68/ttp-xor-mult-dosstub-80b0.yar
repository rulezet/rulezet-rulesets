rule TTP_XOR_MULT_DOSStub_80b0 {
  strings:
    $key_80b0 = { d4 d8 [2] a0 c0 [2] e7 c2 [2] a0 d3 [2] ee df [2] e2 d5 [2] f5 de [2] ee 90 [2] d3 }

  condition:
    any of them
}