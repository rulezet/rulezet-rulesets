rule TTP_XOR_MULT_DOSStub_8068 {
  strings:
    $key_8068 = { d4 00 [2] a0 18 [2] e7 1a [2] a0 0b [2] ee 07 [2] e2 0d [2] f5 06 [2] ee 48 [2] d3 }

  condition:
    any of them
}