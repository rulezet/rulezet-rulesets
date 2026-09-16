rule TTP_XOR_MULT_DOSStub_8c26 {
  strings:
    $key_8c26 = { d8 4e [2] ac 56 [2] eb 54 [2] ac 45 [2] e2 49 [2] ee 43 [2] f9 48 [2] e2 06 [2] df }

  condition:
    any of them
}