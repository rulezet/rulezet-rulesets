rule TTP_XOR_MULT_DOSStub_8cd1 {
  strings:
    $key_8cd1 = { d8 b9 [2] ac a1 [2] eb a3 [2] ac b2 [2] e2 be [2] ee b4 [2] f9 bf [2] e2 f1 [2] df }

  condition:
    any of them
}