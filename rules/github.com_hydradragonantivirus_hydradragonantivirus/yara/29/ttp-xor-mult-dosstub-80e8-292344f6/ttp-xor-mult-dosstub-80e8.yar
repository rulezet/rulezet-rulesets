rule TTP_XOR_MULT_DOSStub_80e8 {
  strings:
    $key_80e8 = { d4 80 [2] a0 98 [2] e7 9a [2] a0 8b [2] ee 87 [2] e2 8d [2] f5 86 [2] ee c8 [2] d3 }

  condition:
    any of them
}