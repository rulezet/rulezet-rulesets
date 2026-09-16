rule TTP_XOR_MULT_DOSStub_8046 {
  strings:
    $key_8046 = { d4 2e [2] a0 36 [2] e7 34 [2] a0 25 [2] ee 29 [2] e2 23 [2] f5 28 [2] ee 66 [2] d3 }

  condition:
    any of them
}