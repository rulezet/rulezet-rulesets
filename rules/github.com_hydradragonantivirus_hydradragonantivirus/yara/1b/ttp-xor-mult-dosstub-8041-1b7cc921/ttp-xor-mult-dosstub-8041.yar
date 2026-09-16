rule TTP_XOR_MULT_DOSStub_8041 {
  strings:
    $key_8041 = { d4 29 [2] a0 31 [2] e7 33 [2] a0 22 [2] ee 2e [2] e2 24 [2] f5 2f [2] ee 61 [2] d3 }

  condition:
    any of them
}