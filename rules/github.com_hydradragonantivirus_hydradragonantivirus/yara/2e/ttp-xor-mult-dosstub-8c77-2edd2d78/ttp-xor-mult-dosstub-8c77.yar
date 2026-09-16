rule TTP_XOR_MULT_DOSStub_8c77 {
  strings:
    $key_8c77 = { d8 1f [2] ac 07 [2] eb 05 [2] ac 14 [2] e2 18 [2] ee 12 [2] f9 19 [2] e2 57 [2] df }

  condition:
    any of them
}