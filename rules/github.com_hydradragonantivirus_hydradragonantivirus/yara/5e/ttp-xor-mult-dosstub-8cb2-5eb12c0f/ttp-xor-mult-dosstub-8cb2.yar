rule TTP_XOR_MULT_DOSStub_8cb2 {
  strings:
    $key_8cb2 = { d8 da [2] ac c2 [2] eb c0 [2] ac d1 [2] e2 dd [2] ee d7 [2] f9 dc [2] e2 92 [2] df }

  condition:
    any of them
}