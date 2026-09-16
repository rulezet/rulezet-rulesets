rule TTP_XOR_MULT_DOSStub_8033 {
  strings:
    $key_8033 = { d4 5b [2] a0 43 [2] e7 41 [2] a0 50 [2] ee 5c [2] e2 56 [2] f5 5d [2] ee 13 [2] d3 }

  condition:
    any of them
}