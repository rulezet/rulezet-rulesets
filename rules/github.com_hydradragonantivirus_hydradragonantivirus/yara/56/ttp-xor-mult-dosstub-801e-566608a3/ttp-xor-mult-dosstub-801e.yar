rule TTP_XOR_MULT_DOSStub_801e {
  strings:
    $key_801e = { d4 76 [2] a0 6e [2] e7 6c [2] a0 7d [2] ee 71 [2] e2 7b [2] f5 70 [2] ee 3e [2] d3 }

  condition:
    any of them
}