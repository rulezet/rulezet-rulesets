rule TTP_XOR_MULT_DOSStub_8cfa {
  strings:
    $key_8cfa = { d8 92 [2] ac 8a [2] eb 88 [2] ac 99 [2] e2 95 [2] ee 9f [2] f9 94 [2] e2 da [2] df }

  condition:
    any of them
}