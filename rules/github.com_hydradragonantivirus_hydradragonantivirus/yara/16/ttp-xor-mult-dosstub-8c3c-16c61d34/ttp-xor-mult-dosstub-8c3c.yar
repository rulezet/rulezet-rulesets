rule TTP_XOR_MULT_DOSStub_8c3c {
  strings:
    $key_8c3c = { d8 54 [2] ac 4c [2] eb 4e [2] ac 5f [2] e2 53 [2] ee 59 [2] f9 52 [2] e2 1c [2] df }

  condition:
    any of them
}