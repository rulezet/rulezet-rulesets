rule TTP_XOR_MULT_DOSStub_8c4c {
  strings:
    $key_8c4c = { d8 24 [2] ac 3c [2] eb 3e [2] ac 2f [2] e2 23 [2] ee 29 [2] f9 22 [2] e2 6c [2] df }

  condition:
    any of them
}