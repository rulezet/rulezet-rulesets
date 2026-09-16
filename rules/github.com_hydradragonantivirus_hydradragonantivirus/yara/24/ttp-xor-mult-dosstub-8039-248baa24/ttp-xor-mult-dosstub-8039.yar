rule TTP_XOR_MULT_DOSStub_8039 {
  strings:
    $key_8039 = { d4 51 [2] a0 49 [2] e7 4b [2] a0 5a [2] ee 56 [2] e2 5c [2] f5 57 [2] ee 19 [2] d3 }

  condition:
    any of them
}