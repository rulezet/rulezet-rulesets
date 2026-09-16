rule TTP_XOR_MULT_DOSStub_8c38 {
  strings:
    $key_8c38 = { d8 50 [2] ac 48 [2] eb 4a [2] ac 5b [2] e2 57 [2] ee 5d [2] f9 56 [2] e2 18 [2] df }

  condition:
    any of them
}