rule TTP_XOR_MULT_DOSStub_8024 {
  strings:
    $key_8024 = { d4 4c [2] a0 54 [2] e7 56 [2] a0 47 [2] ee 4b [2] e2 41 [2] f5 4a [2] ee 04 [2] d3 }

  condition:
    any of them
}