rule TTP_XOR_MULT_DOSStub_807d {
  strings:
    $key_807d = { d4 15 [2] a0 0d [2] e7 0f [2] a0 1e [2] ee 12 [2] e2 18 [2] f5 13 [2] ee 5d [2] d3 }

  condition:
    any of them
}