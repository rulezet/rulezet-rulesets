rule TTP_XOR_MULT_DOSStub_8c83 {
  strings:
    $key_8c83 = { d8 eb [2] ac f3 [2] eb f1 [2] ac e0 [2] e2 ec [2] ee e6 [2] f9 ed [2] e2 a3 [2] df }

  condition:
    any of them
}