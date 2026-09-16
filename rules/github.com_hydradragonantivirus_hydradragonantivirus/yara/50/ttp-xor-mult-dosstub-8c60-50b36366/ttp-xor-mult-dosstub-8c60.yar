rule TTP_XOR_MULT_DOSStub_8c60 {
  strings:
    $key_8c60 = { d8 08 [2] ac 10 [2] eb 12 [2] ac 03 [2] e2 0f [2] ee 05 [2] f9 0e [2] e2 40 [2] df }

  condition:
    any of them
}