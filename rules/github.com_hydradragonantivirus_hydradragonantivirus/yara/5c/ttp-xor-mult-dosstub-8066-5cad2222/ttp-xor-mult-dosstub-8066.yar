rule TTP_XOR_MULT_DOSStub_8066 {
  strings:
    $key_8066 = { d4 0e [2] a0 16 [2] e7 14 [2] a0 05 [2] ee 09 [2] e2 03 [2] f5 08 [2] ee 46 [2] d3 }

  condition:
    any of them
}