rule TTP_XOR_MULT_DOSStub_8cb5 {
  strings:
    $key_8cb5 = { d8 dd [2] ac c5 [2] eb c7 [2] ac d6 [2] e2 da [2] ee d0 [2] f9 db [2] e2 95 [2] df }

  condition:
    any of them
}