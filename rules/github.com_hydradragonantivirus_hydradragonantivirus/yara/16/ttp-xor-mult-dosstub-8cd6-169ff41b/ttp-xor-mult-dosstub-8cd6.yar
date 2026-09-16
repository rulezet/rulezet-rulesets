rule TTP_XOR_MULT_DOSStub_8cd6 {
  strings:
    $key_8cd6 = { d8 be [2] ac a6 [2] eb a4 [2] ac b5 [2] e2 b9 [2] ee b3 [2] f9 b8 [2] e2 f6 [2] df }

  condition:
    any of them
}