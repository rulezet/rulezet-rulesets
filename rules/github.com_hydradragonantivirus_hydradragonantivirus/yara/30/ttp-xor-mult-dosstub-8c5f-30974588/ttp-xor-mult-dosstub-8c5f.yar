rule TTP_XOR_MULT_DOSStub_8c5f {
  strings:
    $key_8c5f = { d8 37 [2] ac 2f [2] eb 2d [2] ac 3c [2] e2 30 [2] ee 3a [2] f9 31 [2] e2 7f [2] df }

  condition:
    any of them
}