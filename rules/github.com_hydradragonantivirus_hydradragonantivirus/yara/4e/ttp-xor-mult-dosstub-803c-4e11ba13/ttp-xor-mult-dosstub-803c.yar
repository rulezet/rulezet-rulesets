rule TTP_XOR_MULT_DOSStub_803c {
  strings:
    $key_803c = { d4 54 [2] a0 4c [2] e7 4e [2] a0 5f [2] ee 53 [2] e2 59 [2] f5 52 [2] ee 1c [2] d3 }

  condition:
    any of them
}