rule TTP_XOR_MULT_DOSStub_8c0e {
  strings:
    $key_8c0e = { d8 66 [2] ac 7e [2] eb 7c [2] ac 6d [2] e2 61 [2] ee 6b [2] f9 60 [2] e2 2e [2] df }

  condition:
    any of them
}