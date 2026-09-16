rule TTP_XOR_MULT_DOSStub_8001 {
  strings:
    $key_8001 = { d4 69 [2] a0 71 [2] e7 73 [2] a0 62 [2] ee 6e [2] e2 64 [2] f5 6f [2] ee 21 [2] d3 }

  condition:
    any of them
}