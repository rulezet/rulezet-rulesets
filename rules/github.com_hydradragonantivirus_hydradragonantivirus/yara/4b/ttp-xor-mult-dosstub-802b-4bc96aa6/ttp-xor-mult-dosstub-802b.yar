rule TTP_XOR_MULT_DOSStub_802b {
  strings:
    $key_802b = { d4 43 [2] a0 5b [2] e7 59 [2] a0 48 [2] ee 44 [2] e2 4e [2] f5 45 [2] ee 0b [2] d3 }

  condition:
    any of them
}