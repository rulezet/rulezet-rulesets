rule TTP_XOR_MULT_DOSStub_8c49 {
  strings:
    $key_8c49 = { d8 21 [2] ac 39 [2] eb 3b [2] ac 2a [2] e2 26 [2] ee 2c [2] f9 27 [2] e2 69 [2] df }

  condition:
    any of them
}