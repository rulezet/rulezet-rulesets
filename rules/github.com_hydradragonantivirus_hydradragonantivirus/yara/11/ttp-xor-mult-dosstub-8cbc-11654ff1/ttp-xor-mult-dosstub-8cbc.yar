rule TTP_XOR_MULT_DOSStub_8cbc {
  strings:
    $key_8cbc = { d8 d4 [2] ac cc [2] eb ce [2] ac df [2] e2 d3 [2] ee d9 [2] f9 d2 [2] e2 9c [2] df }

  condition:
    any of them
}