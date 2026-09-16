rule TTP_XOR_MULT_DOSStub_8060 {
  strings:
    $key_8060 = { d4 08 [2] a0 10 [2] e7 12 [2] a0 03 [2] ee 0f [2] e2 05 [2] f5 0e [2] ee 40 [2] d3 }

  condition:
    any of them
}