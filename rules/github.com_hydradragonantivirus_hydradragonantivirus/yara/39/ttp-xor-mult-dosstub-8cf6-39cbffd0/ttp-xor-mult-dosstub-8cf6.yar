rule TTP_XOR_MULT_DOSStub_8cf6 {
  strings:
    $key_8cf6 = { d8 9e [2] ac 86 [2] eb 84 [2] ac 95 [2] e2 99 [2] ee 93 [2] f9 98 [2] e2 d6 [2] df }

  condition:
    any of them
}