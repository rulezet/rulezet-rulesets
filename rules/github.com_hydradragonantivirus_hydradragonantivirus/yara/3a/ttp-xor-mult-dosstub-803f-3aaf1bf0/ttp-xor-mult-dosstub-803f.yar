rule TTP_XOR_MULT_DOSStub_803f {
  strings:
    $key_803f = { d4 57 [2] a0 4f [2] e7 4d [2] a0 5c [2] ee 50 [2] e2 5a [2] f5 51 [2] ee 1f [2] d3 }

  condition:
    any of them
}