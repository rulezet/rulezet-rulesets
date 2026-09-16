rule TTP_XOR_MULT_DOSStub_8ca7 {
  strings:
    $key_8ca7 = { d8 cf [2] ac d7 [2] eb d5 [2] ac c4 [2] e2 c8 [2] ee c2 [2] f9 c9 [2] e2 87 [2] df }

  condition:
    any of them
}