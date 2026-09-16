rule TTP_XOR_MULT_DOSStub_8c29 {
  strings:
    $key_8c29 = { d8 41 [2] ac 59 [2] eb 5b [2] ac 4a [2] e2 46 [2] ee 4c [2] f9 47 [2] e2 09 [2] df }

  condition:
    any of them
}