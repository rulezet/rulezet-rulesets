rule TTP_XOR_MULT_DOSStub_8cce {
  strings:
    $key_8cce = { d8 a6 [2] ac be [2] eb bc [2] ac ad [2] e2 a1 [2] ee ab [2] f9 a0 [2] e2 ee [2] df }

  condition:
    any of them
}