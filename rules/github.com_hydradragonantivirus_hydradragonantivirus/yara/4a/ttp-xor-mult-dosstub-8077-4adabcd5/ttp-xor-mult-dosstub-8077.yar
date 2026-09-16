rule TTP_XOR_MULT_DOSStub_8077 {
  strings:
    $key_8077 = { d4 1f [2] a0 07 [2] e7 05 [2] a0 14 [2] ee 18 [2] e2 12 [2] f5 19 [2] ee 57 [2] d3 }

  condition:
    any of them
}