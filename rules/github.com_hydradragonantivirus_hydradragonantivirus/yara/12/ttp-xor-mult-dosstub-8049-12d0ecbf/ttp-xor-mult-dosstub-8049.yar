rule TTP_XOR_MULT_DOSStub_8049 {
  strings:
    $key_8049 = { d4 21 [2] a0 39 [2] e7 3b [2] a0 2a [2] ee 26 [2] e2 2c [2] f5 27 [2] ee 69 [2] d3 }

  condition:
    any of them
}