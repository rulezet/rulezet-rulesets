rule TTP_XOR_MULT_DOSStub_8c76 {
  strings:
    $key_8c76 = { d8 1e [2] ac 06 [2] eb 04 [2] ac 15 [2] e2 19 [2] ee 13 [2] f9 18 [2] e2 56 [2] df }

  condition:
    any of them
}