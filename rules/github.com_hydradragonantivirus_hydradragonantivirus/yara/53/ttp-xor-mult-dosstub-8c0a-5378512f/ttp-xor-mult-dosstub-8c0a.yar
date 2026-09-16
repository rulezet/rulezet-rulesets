rule TTP_XOR_MULT_DOSStub_8c0a {
  strings:
    $key_8c0a = { d8 62 [2] ac 7a [2] eb 78 [2] ac 69 [2] e2 65 [2] ee 6f [2] f9 64 [2] e2 2a [2] df }

  condition:
    any of them
}