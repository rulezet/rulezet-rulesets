rule TTP_XOR_MULT_DOSStub_8047 {
  strings:
    $key_8047 = { d4 2f [2] a0 37 [2] e7 35 [2] a0 24 [2] ee 28 [2] e2 22 [2] f5 29 [2] ee 67 [2] d3 }

  condition:
    any of them
}