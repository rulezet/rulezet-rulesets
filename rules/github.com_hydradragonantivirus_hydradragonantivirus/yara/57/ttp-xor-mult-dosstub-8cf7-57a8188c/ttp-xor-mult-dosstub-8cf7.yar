rule TTP_XOR_MULT_DOSStub_8cf7 {
  strings:
    $key_8cf7 = { d8 9f [2] ac 87 [2] eb 85 [2] ac 94 [2] e2 98 [2] ee 92 [2] f9 99 [2] e2 d7 [2] df }

  condition:
    any of them
}