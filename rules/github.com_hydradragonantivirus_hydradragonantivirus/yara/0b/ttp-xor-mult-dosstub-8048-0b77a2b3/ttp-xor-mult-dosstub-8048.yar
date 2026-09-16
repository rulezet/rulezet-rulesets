rule TTP_XOR_MULT_DOSStub_8048 {
  strings:
    $key_8048 = { d4 20 [2] a0 38 [2] e7 3a [2] a0 2b [2] ee 27 [2] e2 2d [2] f5 26 [2] ee 68 [2] d3 }

  condition:
    any of them
}