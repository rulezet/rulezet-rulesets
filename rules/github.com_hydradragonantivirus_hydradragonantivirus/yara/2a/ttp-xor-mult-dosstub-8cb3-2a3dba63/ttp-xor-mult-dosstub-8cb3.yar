rule TTP_XOR_MULT_DOSStub_8cb3 {
  strings:
    $key_8cb3 = { d8 db [2] ac c3 [2] eb c1 [2] ac d0 [2] e2 dc [2] ee d6 [2] f9 dd [2] e2 93 [2] df }

  condition:
    any of them
}