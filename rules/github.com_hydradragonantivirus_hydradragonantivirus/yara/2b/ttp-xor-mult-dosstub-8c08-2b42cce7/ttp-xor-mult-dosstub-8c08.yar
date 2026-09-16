rule TTP_XOR_MULT_DOSStub_8c08 {
  strings:
    $key_8c08 = { d8 60 [2] ac 78 [2] eb 7a [2] ac 6b [2] e2 67 [2] ee 6d [2] f9 66 [2] e2 28 [2] df }

  condition:
    any of them
}