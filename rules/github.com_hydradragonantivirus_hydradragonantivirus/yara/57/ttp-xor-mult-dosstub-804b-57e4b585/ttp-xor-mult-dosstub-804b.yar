rule TTP_XOR_MULT_DOSStub_804b {
  strings:
    $key_804b = { d4 23 [2] a0 3b [2] e7 39 [2] a0 28 [2] ee 24 [2] e2 2e [2] f5 25 [2] ee 6b [2] d3 }

  condition:
    any of them
}