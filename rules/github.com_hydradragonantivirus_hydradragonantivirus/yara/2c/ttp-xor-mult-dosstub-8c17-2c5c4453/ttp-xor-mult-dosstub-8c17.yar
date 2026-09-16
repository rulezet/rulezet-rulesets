rule TTP_XOR_MULT_DOSStub_8c17 {
  strings:
    $key_8c17 = { d8 7f [2] ac 67 [2] eb 65 [2] ac 74 [2] e2 78 [2] ee 72 [2] f9 79 [2] e2 37 [2] df }

  condition:
    any of them
}