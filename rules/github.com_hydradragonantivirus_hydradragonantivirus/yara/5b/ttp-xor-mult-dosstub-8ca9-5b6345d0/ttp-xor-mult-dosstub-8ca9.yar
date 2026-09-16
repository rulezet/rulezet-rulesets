rule TTP_XOR_MULT_DOSStub_8ca9 {
  strings:
    $key_8ca9 = { d8 c1 [2] ac d9 [2] eb db [2] ac ca [2] e2 c6 [2] ee cc [2] f9 c7 [2] e2 89 [2] df }

  condition:
    any of them
}