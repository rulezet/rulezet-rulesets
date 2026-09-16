rule TTP_XOR_MULT_DOSStub_8ce5 {
  strings:
    $key_8ce5 = { d8 8d [2] ac 95 [2] eb 97 [2] ac 86 [2] e2 8a [2] ee 80 [2] f9 8b [2] e2 c5 [2] df }

  condition:
    any of them
}