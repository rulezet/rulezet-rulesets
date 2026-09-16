rule TTP_XOR_MULT_DOSStub_8c9e {
  strings:
    $key_8c9e = { d8 f6 [2] ac ee [2] eb ec [2] ac fd [2] e2 f1 [2] ee fb [2] f9 f0 [2] e2 be [2] df }

  condition:
    any of them
}