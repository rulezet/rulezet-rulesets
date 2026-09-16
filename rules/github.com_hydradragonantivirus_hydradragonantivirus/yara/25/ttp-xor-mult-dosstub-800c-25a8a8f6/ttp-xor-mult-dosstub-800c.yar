rule TTP_XOR_MULT_DOSStub_800c {
  strings:
    $key_800c = { d4 64 [2] a0 7c [2] e7 7e [2] a0 6f [2] ee 63 [2] e2 69 [2] f5 62 [2] ee 2c [2] d3 }

  condition:
    any of them
}