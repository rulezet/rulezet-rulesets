rule TTP_XOR_MULT_DOSStub_8055 {
  strings:
    $key_8055 = { d4 3d [2] a0 25 [2] e7 27 [2] a0 36 [2] ee 3a [2] e2 30 [2] f5 3b [2] ee 75 [2] d3 }

  condition:
    any of them
}