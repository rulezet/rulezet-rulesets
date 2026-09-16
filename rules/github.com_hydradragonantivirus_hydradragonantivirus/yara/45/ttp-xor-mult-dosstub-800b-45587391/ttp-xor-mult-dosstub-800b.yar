rule TTP_XOR_MULT_DOSStub_800b {
  strings:
    $key_800b = { d4 63 [2] a0 7b [2] e7 79 [2] a0 68 [2] ee 64 [2] e2 6e [2] f5 65 [2] ee 2b [2] d3 }

  condition:
    any of them
}