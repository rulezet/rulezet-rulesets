rule TTP_XOR_MULT_DOSStub_8cd9 {
  strings:
    $key_8cd9 = { d8 b1 [2] ac a9 [2] eb ab [2] ac ba [2] e2 b6 [2] ee bc [2] f9 b7 [2] e2 f9 [2] df }

  condition:
    any of them
}