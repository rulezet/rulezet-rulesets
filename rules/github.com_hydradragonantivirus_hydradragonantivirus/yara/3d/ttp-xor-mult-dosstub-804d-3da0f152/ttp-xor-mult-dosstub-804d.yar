rule TTP_XOR_MULT_DOSStub_804d {
  strings:
    $key_804d = { d4 25 [2] a0 3d [2] e7 3f [2] a0 2e [2] ee 22 [2] e2 28 [2] f5 23 [2] ee 6d [2] d3 }

  condition:
    any of them
}