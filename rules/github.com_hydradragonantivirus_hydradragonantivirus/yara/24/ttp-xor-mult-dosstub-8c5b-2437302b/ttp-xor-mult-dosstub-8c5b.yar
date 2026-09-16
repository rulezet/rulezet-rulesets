rule TTP_XOR_MULT_DOSStub_8c5b {
  strings:
    $key_8c5b = { d8 33 [2] ac 2b [2] eb 29 [2] ac 38 [2] e2 34 [2] ee 3e [2] f9 35 [2] e2 7b [2] df }

  condition:
    any of them
}