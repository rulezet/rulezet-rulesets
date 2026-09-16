rule TTP_XOR_MULT_DOSStub_8c20 {
  strings:
    $key_8c20 = { d8 48 [2] ac 50 [2] eb 52 [2] ac 43 [2] e2 4f [2] ee 45 [2] f9 4e [2] e2 00 [2] df }

  condition:
    any of them
}