rule TTP_XOR_MULT_DOSStub_80a3 {
  strings:
    $key_80a3 = { d4 cb [2] a0 d3 [2] e7 d1 [2] a0 c0 [2] ee cc [2] e2 c6 [2] f5 cd [2] ee 83 [2] d3 }

  condition:
    any of them
}