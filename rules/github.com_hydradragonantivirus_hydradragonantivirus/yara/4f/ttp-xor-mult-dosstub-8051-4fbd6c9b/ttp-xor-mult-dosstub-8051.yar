rule TTP_XOR_MULT_DOSStub_8051 {
  strings:
    $key_8051 = { d4 39 [2] a0 21 [2] e7 23 [2] a0 32 [2] ee 3e [2] e2 34 [2] f5 3f [2] ee 71 [2] d3 }

  condition:
    any of them
}