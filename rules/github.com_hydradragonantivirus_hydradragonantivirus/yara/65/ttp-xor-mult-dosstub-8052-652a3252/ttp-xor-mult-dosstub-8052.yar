rule TTP_XOR_MULT_DOSStub_8052 {
  strings:
    $key_8052 = { d4 3a [2] a0 22 [2] e7 20 [2] a0 31 [2] ee 3d [2] e2 37 [2] f5 3c [2] ee 72 [2] d3 }

  condition:
    any of them
}