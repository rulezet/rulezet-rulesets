rule TTP_XOR_MULT_DOSStub_8c85 {
  strings:
    $key_8c85 = { d8 ed [2] ac f5 [2] eb f7 [2] ac e6 [2] e2 ea [2] ee e0 [2] f9 eb [2] e2 a5 [2] df }

  condition:
    any of them
}