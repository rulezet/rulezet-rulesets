rule TTP_XOR_MULT_DOSStub_8cb7 {
  strings:
    $key_8cb7 = { d8 df [2] ac c7 [2] eb c5 [2] ac d4 [2] e2 d8 [2] ee d2 [2] f9 d9 [2] e2 97 [2] df }

  condition:
    any of them
}