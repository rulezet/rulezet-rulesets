rule TTP_XOR_MULT_DOSStub_8ccb {
  strings:
    $key_8ccb = { d8 a3 [2] ac bb [2] eb b9 [2] ac a8 [2] e2 a4 [2] ee ae [2] f9 a5 [2] e2 eb [2] df }

  condition:
    any of them
}