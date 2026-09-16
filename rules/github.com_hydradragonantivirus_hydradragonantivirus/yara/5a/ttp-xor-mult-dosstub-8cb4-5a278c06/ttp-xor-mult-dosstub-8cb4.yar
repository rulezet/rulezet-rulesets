rule TTP_XOR_MULT_DOSStub_8cb4 {
  strings:
    $key_8cb4 = { d8 dc [2] ac c4 [2] eb c6 [2] ac d7 [2] e2 db [2] ee d1 [2] f9 da [2] e2 94 [2] df }

  condition:
    any of them
}