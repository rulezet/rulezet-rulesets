rule TTP_XOR_MULT_DOSStub_8ce9 {
  strings:
    $key_8ce9 = { d8 81 [2] ac 99 [2] eb 9b [2] ac 8a [2] e2 86 [2] ee 8c [2] f9 87 [2] e2 c9 [2] df }

  condition:
    any of them
}