rule TTP_XOR_MULT_DOSStub_80ee {
  strings:
    $key_80ee = { d4 86 [2] a0 9e [2] e7 9c [2] a0 8d [2] ee 81 [2] e2 8b [2] f5 80 [2] ee ce [2] d3 }

  condition:
    any of them
}