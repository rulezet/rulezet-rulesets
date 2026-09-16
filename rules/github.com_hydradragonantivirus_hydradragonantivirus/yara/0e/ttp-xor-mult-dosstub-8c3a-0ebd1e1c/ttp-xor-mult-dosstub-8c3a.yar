rule TTP_XOR_MULT_DOSStub_8c3a {
  strings:
    $key_8c3a = { d8 52 [2] ac 4a [2] eb 48 [2] ac 59 [2] e2 55 [2] ee 5f [2] f9 54 [2] e2 1a [2] df }

  condition:
    any of them
}