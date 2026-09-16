rule TTP_XOR_MULT_DOSStub_8997 {
  strings:
    $key_8997 = { dd ff [2] a9 e7 [2] ee e5 [2] a9 f4 [2] e7 f8 [2] eb f2 [2] fc f9 [2] e7 b7 [2] da }

  condition:
    any of them
}