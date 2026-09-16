rule TTP_XOR_MULT_DOSStub_8036 {
  strings:
    $key_8036 = { d4 5e [2] a0 46 [2] e7 44 [2] a0 55 [2] ee 59 [2] e2 53 [2] f5 58 [2] ee 16 [2] d3 }

  condition:
    any of them
}