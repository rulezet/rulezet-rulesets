rule TTP_XOR_MULT_DOSStub_8030 {
  strings:
    $key_8030 = { d4 58 [2] a0 40 [2] e7 42 [2] a0 53 [2] ee 5f [2] e2 55 [2] f5 5e [2] ee 10 [2] d3 }

  condition:
    any of them
}