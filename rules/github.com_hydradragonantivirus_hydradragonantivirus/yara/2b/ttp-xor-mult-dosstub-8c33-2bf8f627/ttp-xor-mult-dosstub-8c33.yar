rule TTP_XOR_MULT_DOSStub_8c33 {
  strings:
    $key_8c33 = { d8 5b [2] ac 43 [2] eb 41 [2] ac 50 [2] e2 5c [2] ee 56 [2] f9 5d [2] e2 13 [2] df }

  condition:
    any of them
}