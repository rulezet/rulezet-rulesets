rule TTP_XOR_MULT_DOSStub_8c56 {
  strings:
    $key_8c56 = { d8 3e [2] ac 26 [2] eb 24 [2] ac 35 [2] e2 39 [2] ee 33 [2] f9 38 [2] e2 76 [2] df }

  condition:
    any of them
}