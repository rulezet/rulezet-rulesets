rule TTP_XOR_MULT_DOSStub_8000 {
  strings:
    $key_8000 = { d4 68 [2] a0 70 [2] e7 72 [2] a0 63 [2] ee 6f [2] e2 65 [2] f5 6e [2] ee 20 [2] d3 }

  condition:
    any of them
}