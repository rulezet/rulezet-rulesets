rule TTP_XOR_MULT_DOSStub_802e {
  strings:
    $key_802e = { d4 46 [2] a0 5e [2] e7 5c [2] a0 4d [2] ee 41 [2] e2 4b [2] f5 40 [2] ee 0e [2] d3 }

  condition:
    any of them
}