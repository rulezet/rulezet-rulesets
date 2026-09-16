rule TTP_XOR_MULT_DOSStub_8c80 {
  strings:
    $key_8c80 = { d8 e8 [2] ac f0 [2] eb f2 [2] ac e3 [2] e2 ef [2] ee e5 [2] f9 ee [2] e2 a0 [2] df }

  condition:
    any of them
}