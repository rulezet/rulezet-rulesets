rule TTP_XOR_MULT_DOSStub_8c95 {
  strings:
    $key_8c95 = { d8 fd [2] ac e5 [2] eb e7 [2] ac f6 [2] e2 fa [2] ee f0 [2] f9 fb [2] e2 b5 [2] df }

  condition:
    any of them
}