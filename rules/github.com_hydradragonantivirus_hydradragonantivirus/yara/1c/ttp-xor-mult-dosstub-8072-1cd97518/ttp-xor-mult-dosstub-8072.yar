rule TTP_XOR_MULT_DOSStub_8072 {
  strings:
    $key_8072 = { d4 1a [2] a0 02 [2] e7 00 [2] a0 11 [2] ee 1d [2] e2 17 [2] f5 1c [2] ee 52 [2] d3 }

  condition:
    any of them
}