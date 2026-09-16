rule TTP_XOR_MULT_DOSStub_8c79 {
  strings:
    $key_8c79 = { d8 11 [2] ac 09 [2] eb 0b [2] ac 1a [2] e2 16 [2] ee 1c [2] f9 17 [2] e2 59 [2] df }

  condition:
    any of them
}