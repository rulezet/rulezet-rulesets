rule TTP_XOR_MULT_DOSStub_800e {
  strings:
    $key_800e = { d4 66 [2] a0 7e [2] e7 7c [2] a0 6d [2] ee 61 [2] e2 6b [2] f5 60 [2] ee 2e [2] d3 }

  condition:
    any of them
}