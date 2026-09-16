rule TTP_XOR_MULT_DOSStub_8c30 {
  strings:
    $key_8c30 = { d8 58 [2] ac 40 [2] eb 42 [2] ac 53 [2] e2 5f [2] ee 55 [2] f9 5e [2] e2 10 [2] df }

  condition:
    any of them
}