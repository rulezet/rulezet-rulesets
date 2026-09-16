rule TTP_XOR_MULT_DOSStub_8c86 {
  strings:
    $key_8c86 = { d8 ee [2] ac f6 [2] eb f4 [2] ac e5 [2] e2 e9 [2] ee e3 [2] f9 e8 [2] e2 a6 [2] df }

  condition:
    any of them
}