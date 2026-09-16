rule TTP_XOR_MULT_DOSStub_8c21 {
  strings:
    $key_8c21 = { d8 49 [2] ac 51 [2] eb 53 [2] ac 42 [2] e2 4e [2] ee 44 [2] f9 4f [2] e2 01 [2] df }

  condition:
    any of them
}