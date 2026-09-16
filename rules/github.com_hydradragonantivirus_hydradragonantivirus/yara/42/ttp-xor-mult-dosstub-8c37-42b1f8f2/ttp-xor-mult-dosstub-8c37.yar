rule TTP_XOR_MULT_DOSStub_8c37 {
  strings:
    $key_8c37 = { d8 5f [2] ac 47 [2] eb 45 [2] ac 54 [2] e2 58 [2] ee 52 [2] f9 59 [2] e2 17 [2] df }

  condition:
    any of them
}