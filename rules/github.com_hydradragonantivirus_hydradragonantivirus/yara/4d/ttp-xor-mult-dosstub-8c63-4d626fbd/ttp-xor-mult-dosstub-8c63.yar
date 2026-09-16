rule TTP_XOR_MULT_DOSStub_8c63 {
  strings:
    $key_8c63 = { d8 0b [2] ac 13 [2] eb 11 [2] ac 00 [2] e2 0c [2] ee 06 [2] f9 0d [2] e2 43 [2] df }

  condition:
    any of them
}