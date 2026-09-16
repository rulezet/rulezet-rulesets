rule TTP_XOR_MULT_DOSStub_8c66 {
  strings:
    $key_8c66 = { d8 0e [2] ac 16 [2] eb 14 [2] ac 05 [2] e2 09 [2] ee 03 [2] f9 08 [2] e2 46 [2] df }

  condition:
    any of them
}