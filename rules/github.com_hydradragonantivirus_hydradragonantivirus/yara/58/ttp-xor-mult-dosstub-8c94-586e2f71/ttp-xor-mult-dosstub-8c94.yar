rule TTP_XOR_MULT_DOSStub_8c94 {
  strings:
    $key_8c94 = { d8 fc [2] ac e4 [2] eb e6 [2] ac f7 [2] e2 fb [2] ee f1 [2] f9 fa [2] e2 b4 [2] df }

  condition:
    any of them
}