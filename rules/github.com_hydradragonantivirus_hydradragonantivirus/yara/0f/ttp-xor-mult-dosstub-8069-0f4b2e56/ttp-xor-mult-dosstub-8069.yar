rule TTP_XOR_MULT_DOSStub_8069 {
  strings:
    $key_8069 = { d4 01 [2] a0 19 [2] e7 1b [2] a0 0a [2] ee 06 [2] e2 0c [2] f5 07 [2] ee 49 [2] d3 }

  condition:
    any of them
}