rule TTP_XOR_MULT_DOSStub_8c9a {
  strings:
    $key_8c9a = { d8 f2 [2] ac ea [2] eb e8 [2] ac f9 [2] e2 f5 [2] ee ff [2] f9 f4 [2] e2 ba [2] df }

  condition:
    any of them
}