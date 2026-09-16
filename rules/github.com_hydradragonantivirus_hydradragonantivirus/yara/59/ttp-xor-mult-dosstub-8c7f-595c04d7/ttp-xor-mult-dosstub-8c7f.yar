rule TTP_XOR_MULT_DOSStub_8c7f {
  strings:
    $key_8c7f = { d8 17 [2] ac 0f [2] eb 0d [2] ac 1c [2] e2 10 [2] ee 1a [2] f9 11 [2] e2 5f [2] df }

  condition:
    any of them
}