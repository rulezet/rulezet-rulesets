rule TTP_XOR_MULT_DOSStub_8caa {
  strings:
    $key_8caa = { d8 c2 [2] ac da [2] eb d8 [2] ac c9 [2] e2 c5 [2] ee cf [2] f9 c4 [2] e2 8a [2] df }

  condition:
    any of them
}