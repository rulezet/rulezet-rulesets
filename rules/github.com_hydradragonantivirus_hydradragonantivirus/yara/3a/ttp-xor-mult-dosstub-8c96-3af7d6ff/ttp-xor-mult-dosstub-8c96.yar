rule TTP_XOR_MULT_DOSStub_8c96 {
  strings:
    $key_8c96 = { d8 fe [2] ac e6 [2] eb e4 [2] ac f5 [2] e2 f9 [2] ee f3 [2] f9 f8 [2] e2 b6 [2] df }

  condition:
    any of them
}