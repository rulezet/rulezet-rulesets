rule TTP_XOR_MULT_DOSStub_801b {
  strings:
    $key_801b = { d4 73 [2] a0 6b [2] e7 69 [2] a0 78 [2] ee 74 [2] e2 7e [2] f5 75 [2] ee 3b [2] d3 }

  condition:
    any of them
}