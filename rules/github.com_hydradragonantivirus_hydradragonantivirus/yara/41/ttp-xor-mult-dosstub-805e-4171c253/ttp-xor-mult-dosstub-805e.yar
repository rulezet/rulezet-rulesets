rule TTP_XOR_MULT_DOSStub_805e {
  strings:
    $key_805e = { d4 36 [2] a0 2e [2] e7 2c [2] a0 3d [2] ee 31 [2] e2 3b [2] f5 30 [2] ee 7e [2] d3 }

  condition:
    any of them
}