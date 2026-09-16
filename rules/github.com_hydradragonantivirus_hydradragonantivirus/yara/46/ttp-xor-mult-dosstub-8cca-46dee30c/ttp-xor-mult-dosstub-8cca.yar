rule TTP_XOR_MULT_DOSStub_8cca {
  strings:
    $key_8cca = { d8 a2 [2] ac ba [2] eb b8 [2] ac a9 [2] e2 a5 [2] ee af [2] f9 a4 [2] e2 ea [2] df }

  condition:
    any of them
}