rule TTP_XOR_MULT_DOSStub_8c8b {
  strings:
    $key_8c8b = { d8 e3 [2] ac fb [2] eb f9 [2] ac e8 [2] e2 e4 [2] ee ee [2] f9 e5 [2] e2 ab [2] df }

  condition:
    any of them
}