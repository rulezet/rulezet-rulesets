rule TTP_XOR_MULT_DOSStub_8037 {
  strings:
    $key_8037 = { d4 5f [2] a0 47 [2] e7 45 [2] a0 54 [2] ee 58 [2] e2 52 [2] f5 59 [2] ee 17 [2] d3 }

  condition:
    any of them
}