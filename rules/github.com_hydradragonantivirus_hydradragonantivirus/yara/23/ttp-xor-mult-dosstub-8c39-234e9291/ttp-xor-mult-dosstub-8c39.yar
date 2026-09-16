rule TTP_XOR_MULT_DOSStub_8c39 {
  strings:
    $key_8c39 = { d8 51 [2] ac 49 [2] eb 4b [2] ac 5a [2] e2 56 [2] ee 5c [2] f9 57 [2] e2 19 [2] df }

  condition:
    any of them
}