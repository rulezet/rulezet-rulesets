rule TTP_XOR_MULT_DOSStub_8045 {
  strings:
    $key_8045 = { d4 2d [2] a0 35 [2] e7 37 [2] a0 26 [2] ee 2a [2] e2 20 [2] f5 2b [2] ee 65 [2] d3 }

  condition:
    any of them
}