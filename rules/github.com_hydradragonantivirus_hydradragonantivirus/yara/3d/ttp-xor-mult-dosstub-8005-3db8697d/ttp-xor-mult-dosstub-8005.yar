rule TTP_XOR_MULT_DOSStub_8005 {
  strings:
    $key_8005 = { d4 6d [2] a0 75 [2] e7 77 [2] a0 66 [2] ee 6a [2] e2 60 [2] f5 6b [2] ee 25 [2] d3 }

  condition:
    any of them
}