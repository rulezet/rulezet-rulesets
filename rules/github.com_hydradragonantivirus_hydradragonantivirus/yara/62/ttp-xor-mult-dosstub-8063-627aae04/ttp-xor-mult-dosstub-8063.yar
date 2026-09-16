rule TTP_XOR_MULT_DOSStub_8063 {
  strings:
    $key_8063 = { d4 0b [2] a0 13 [2] e7 11 [2] a0 00 [2] ee 0c [2] e2 06 [2] f5 0d [2] ee 43 [2] d3 }

  condition:
    any of them
}