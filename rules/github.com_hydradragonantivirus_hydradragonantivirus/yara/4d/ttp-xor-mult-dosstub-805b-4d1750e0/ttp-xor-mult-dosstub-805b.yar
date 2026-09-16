rule TTP_XOR_MULT_DOSStub_805b {
  strings:
    $key_805b = { d4 33 [2] a0 2b [2] e7 29 [2] a0 38 [2] ee 34 [2] e2 3e [2] f5 35 [2] ee 7b [2] d3 }

  condition:
    any of them
}