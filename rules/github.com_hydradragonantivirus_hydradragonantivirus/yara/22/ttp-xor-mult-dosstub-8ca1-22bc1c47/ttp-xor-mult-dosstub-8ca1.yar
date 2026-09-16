rule TTP_XOR_MULT_DOSStub_8ca1 {
  strings:
    $key_8ca1 = { d8 c9 [2] ac d1 [2] eb d3 [2] ac c2 [2] e2 ce [2] ee c4 [2] f9 cf [2] e2 81 [2] df }

  condition:
    any of them
}