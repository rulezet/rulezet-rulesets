rule TTP_XOR_MULT_DOSStub_8c25 {
  strings:
    $key_8c25 = { d8 4d [2] ac 55 [2] eb 57 [2] ac 46 [2] e2 4a [2] ee 40 [2] f9 4b [2] e2 05 [2] df }

  condition:
    any of them
}