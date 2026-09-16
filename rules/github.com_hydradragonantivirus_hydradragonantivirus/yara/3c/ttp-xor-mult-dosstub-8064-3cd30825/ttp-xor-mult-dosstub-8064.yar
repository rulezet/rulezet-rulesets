rule TTP_XOR_MULT_DOSStub_8064 {
  strings:
    $key_8064 = { d4 0c [2] a0 14 [2] e7 16 [2] a0 07 [2] ee 0b [2] e2 01 [2] f5 0a [2] ee 44 [2] d3 }

  condition:
    any of them
}