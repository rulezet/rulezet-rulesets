rule TTP_XOR_MULT_DOSStub_8004 {
  strings:
    $key_8004 = { d4 6c [2] a0 74 [2] e7 76 [2] a0 67 [2] ee 6b [2] e2 61 [2] f5 6a [2] ee 24 [2] d3 }

  condition:
    any of them
}