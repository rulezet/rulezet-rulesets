rule TTP_XOR_MULT_DOSStub_80e6 {
  strings:
    $key_80e6 = { d4 8e [2] a0 96 [2] e7 94 [2] a0 85 [2] ee 89 [2] e2 83 [2] f5 88 [2] ee c6 [2] d3 }

  condition:
    any of them
}