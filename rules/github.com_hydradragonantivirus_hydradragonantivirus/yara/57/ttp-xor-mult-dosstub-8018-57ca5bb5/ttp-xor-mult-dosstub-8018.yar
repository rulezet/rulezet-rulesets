rule TTP_XOR_MULT_DOSStub_8018 {
  strings:
    $key_8018 = { d4 70 [2] a0 68 [2] e7 6a [2] a0 7b [2] ee 77 [2] e2 7d [2] f5 76 [2] ee 38 [2] d3 }

  condition:
    any of them
}