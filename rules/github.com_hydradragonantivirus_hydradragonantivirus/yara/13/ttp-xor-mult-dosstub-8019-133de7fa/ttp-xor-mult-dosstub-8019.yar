rule TTP_XOR_MULT_DOSStub_8019 {
  strings:
    $key_8019 = { d4 71 [2] a0 69 [2] e7 6b [2] a0 7a [2] ee 76 [2] e2 7c [2] f5 77 [2] ee 39 [2] d3 }

  condition:
    any of them
}