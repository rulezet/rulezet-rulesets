rule TTP_XOR_MULT_DOSStub_8ce2 {
  strings:
    $key_8ce2 = { d8 8a [2] ac 92 [2] eb 90 [2] ac 81 [2] e2 8d [2] ee 87 [2] f9 8c [2] e2 c2 [2] df }

  condition:
    any of them
}