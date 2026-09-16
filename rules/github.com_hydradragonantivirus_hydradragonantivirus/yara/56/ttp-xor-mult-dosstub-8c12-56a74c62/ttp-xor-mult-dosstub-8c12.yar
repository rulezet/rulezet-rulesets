rule TTP_XOR_MULT_DOSStub_8c12 {
  strings:
    $key_8c12 = { d8 7a [2] ac 62 [2] eb 60 [2] ac 71 [2] e2 7d [2] ee 77 [2] f9 7c [2] e2 32 [2] df }

  condition:
    any of them
}