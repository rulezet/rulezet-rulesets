rule TTP_XOR_MULT_DOSStub_8038 {
  strings:
    $key_8038 = { d4 50 [2] a0 48 [2] e7 4a [2] a0 5b [2] ee 57 [2] e2 5d [2] f5 56 [2] ee 18 [2] d3 }

  condition:
    any of them
}