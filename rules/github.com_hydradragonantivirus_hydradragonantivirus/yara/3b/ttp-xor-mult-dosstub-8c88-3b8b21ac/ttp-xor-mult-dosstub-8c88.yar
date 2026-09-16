rule TTP_XOR_MULT_DOSStub_8c88 {
  strings:
    $key_8c88 = { d8 e0 [2] ac f8 [2] eb fa [2] ac eb [2] e2 e7 [2] ee ed [2] f9 e6 [2] e2 a8 [2] df }

  condition:
    any of them
}