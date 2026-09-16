rule TTP_XOR_MULT_DOSStub_8c35 {
  strings:
    $key_8c35 = { d8 5d [2] ac 45 [2] eb 47 [2] ac 56 [2] e2 5a [2] ee 50 [2] f9 5b [2] e2 15 [2] df }

  condition:
    any of them
}