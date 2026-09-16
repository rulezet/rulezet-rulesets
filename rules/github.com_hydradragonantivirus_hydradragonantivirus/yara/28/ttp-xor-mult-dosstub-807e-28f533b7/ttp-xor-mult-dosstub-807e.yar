rule TTP_XOR_MULT_DOSStub_807e {
  strings:
    $key_807e = { d4 16 [2] a0 0e [2] e7 0c [2] a0 1d [2] ee 11 [2] e2 1b [2] f5 10 [2] ee 5e [2] d3 }

  condition:
    any of them
}