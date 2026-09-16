rule TTP_XOR_MULT_DOSStub_8040 {
  strings:
    $key_8040 = { d4 28 [2] a0 30 [2] e7 32 [2] a0 23 [2] ee 2f [2] e2 25 [2] f5 2e [2] ee 60 [2] d3 }

  condition:
    any of them
}