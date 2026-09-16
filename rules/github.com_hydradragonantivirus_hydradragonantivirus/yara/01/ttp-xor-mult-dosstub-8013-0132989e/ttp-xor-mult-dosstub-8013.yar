rule TTP_XOR_MULT_DOSStub_8013 {
  strings:
    $key_8013 = { d4 7b [2] a0 63 [2] e7 61 [2] a0 70 [2] ee 7c [2] e2 76 [2] f5 7d [2] ee 33 [2] d3 }

  condition:
    any of them
}