rule TTP_XOR_MULT_DOSStub_8078 {
  strings:
    $key_8078 = { d4 10 [2] a0 08 [2] e7 0a [2] a0 1b [2] ee 17 [2] e2 1d [2] f5 16 [2] ee 58 [2] d3 }

  condition:
    any of them
}