rule TTP_XOR_MULT_DOSStub_8020 {
  strings:
    $key_8020 = { d4 48 [2] a0 50 [2] e7 52 [2] a0 43 [2] ee 4f [2] e2 45 [2] f5 4e [2] ee 00 [2] d3 }

  condition:
    any of them
}