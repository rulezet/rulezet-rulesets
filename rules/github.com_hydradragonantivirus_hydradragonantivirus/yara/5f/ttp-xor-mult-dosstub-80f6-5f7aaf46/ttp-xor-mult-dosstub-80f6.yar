rule TTP_XOR_MULT_DOSStub_80f6 {
  strings:
    $key_80f6 = { d4 9e [2] a0 86 [2] e7 84 [2] a0 95 [2] ee 99 [2] e2 93 [2] f5 98 [2] ee d6 [2] d3 }

  condition:
    any of them
}