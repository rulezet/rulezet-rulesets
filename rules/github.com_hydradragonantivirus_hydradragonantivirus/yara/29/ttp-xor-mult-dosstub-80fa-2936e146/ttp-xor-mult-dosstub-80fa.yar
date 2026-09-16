rule TTP_XOR_MULT_DOSStub_80fa {
  strings:
    $key_80fa = { d4 92 [2] a0 8a [2] e7 88 [2] a0 99 [2] ee 95 [2] e2 9f [2] f5 94 [2] ee da [2] d3 }

  condition:
    any of them
}