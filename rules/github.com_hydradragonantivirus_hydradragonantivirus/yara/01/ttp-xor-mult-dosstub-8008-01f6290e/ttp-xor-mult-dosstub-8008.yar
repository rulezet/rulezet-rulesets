rule TTP_XOR_MULT_DOSStub_8008 {
  strings:
    $key_8008 = { d4 60 [2] a0 78 [2] e7 7a [2] a0 6b [2] ee 67 [2] e2 6d [2] f5 66 [2] ee 28 [2] d3 }

  condition:
    any of them
}