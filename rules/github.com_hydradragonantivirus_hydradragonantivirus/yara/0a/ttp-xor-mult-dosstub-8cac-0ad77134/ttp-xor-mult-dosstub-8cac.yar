rule TTP_XOR_MULT_DOSStub_8cac {
  strings:
    $key_8cac = { d8 c4 [2] ac dc [2] eb de [2] ac cf [2] e2 c3 [2] ee c9 [2] f9 c2 [2] e2 8c [2] df }

  condition:
    any of them
}