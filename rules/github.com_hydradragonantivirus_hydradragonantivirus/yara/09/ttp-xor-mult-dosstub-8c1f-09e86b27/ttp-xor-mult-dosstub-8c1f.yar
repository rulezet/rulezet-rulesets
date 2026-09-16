rule TTP_XOR_MULT_DOSStub_8c1f {
  strings:
    $key_8c1f = { d8 77 [2] ac 6f [2] eb 6d [2] ac 7c [2] e2 70 [2] ee 7a [2] f9 71 [2] e2 3f [2] df }

  condition:
    any of them
}