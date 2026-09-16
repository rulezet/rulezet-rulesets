rule TTP_XOR_MULT_DOSStub_8071 {
  strings:
    $key_8071 = { d4 19 [2] a0 01 [2] e7 03 [2] a0 12 [2] ee 1e [2] e2 14 [2] f5 1f [2] ee 51 [2] d3 }

  condition:
    any of them
}