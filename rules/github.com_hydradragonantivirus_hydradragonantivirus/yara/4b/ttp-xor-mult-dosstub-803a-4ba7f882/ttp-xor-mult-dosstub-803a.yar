rule TTP_XOR_MULT_DOSStub_803a {
  strings:
    $key_803a = { d4 52 [2] a0 4a [2] e7 48 [2] a0 59 [2] ee 55 [2] e2 5f [2] f5 54 [2] ee 1a [2] d3 }

  condition:
    any of them
}