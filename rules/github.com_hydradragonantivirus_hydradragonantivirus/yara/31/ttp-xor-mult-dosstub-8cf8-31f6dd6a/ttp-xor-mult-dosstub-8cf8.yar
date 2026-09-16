rule TTP_XOR_MULT_DOSStub_8cf8 {
  strings:
    $key_8cf8 = { d8 90 [2] ac 88 [2] eb 8a [2] ac 9b [2] e2 97 [2] ee 9d [2] f9 96 [2] e2 d8 [2] df }

  condition:
    any of them
}