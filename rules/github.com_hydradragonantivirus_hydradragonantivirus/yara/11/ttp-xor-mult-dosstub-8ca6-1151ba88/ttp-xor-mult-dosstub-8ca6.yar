rule TTP_XOR_MULT_DOSStub_8ca6 {
  strings:
    $key_8ca6 = { d8 ce [2] ac d6 [2] eb d4 [2] ac c5 [2] e2 c9 [2] ee c3 [2] f9 c8 [2] e2 86 [2] df }

  condition:
    any of them
}