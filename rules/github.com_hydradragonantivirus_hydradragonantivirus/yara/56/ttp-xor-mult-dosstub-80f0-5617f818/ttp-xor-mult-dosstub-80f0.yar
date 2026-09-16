rule TTP_XOR_MULT_DOSStub_80f0 {
  strings:
    $key_80f0 = { d4 98 [2] a0 80 [2] e7 82 [2] a0 93 [2] ee 9f [2] e2 95 [2] f5 9e [2] ee d0 [2] d3 }

  condition:
    any of them
}