rule TTP_XOR_MULT_DOSStub_8c75 {
  strings:
    $key_8c75 = { d8 1d [2] ac 05 [2] eb 07 [2] ac 16 [2] e2 1a [2] ee 10 [2] f9 1b [2] e2 55 [2] df }

  condition:
    any of them
}