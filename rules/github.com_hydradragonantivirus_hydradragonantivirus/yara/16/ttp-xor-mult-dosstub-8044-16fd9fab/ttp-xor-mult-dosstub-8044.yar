rule TTP_XOR_MULT_DOSStub_8044 {
  strings:
    $key_8044 = { d4 2c [2] a0 34 [2] e7 36 [2] a0 27 [2] ee 2b [2] e2 21 [2] f5 2a [2] ee 64 [2] d3 }

  condition:
    any of them
}