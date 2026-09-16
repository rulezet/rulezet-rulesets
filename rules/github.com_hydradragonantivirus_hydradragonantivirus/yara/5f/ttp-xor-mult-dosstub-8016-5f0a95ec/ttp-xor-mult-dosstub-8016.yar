rule TTP_XOR_MULT_DOSStub_8016 {
  strings:
    $key_8016 = { d4 7e [2] a0 66 [2] e7 64 [2] a0 75 [2] ee 79 [2] e2 73 [2] f5 78 [2] ee 36 [2] d3 }

  condition:
    any of them
}