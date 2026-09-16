rule TTP_XOR_MULT_DOSStub_89b6 {
  strings:
    $key_89b6 = { dd de [2] a9 c6 [2] ee c4 [2] a9 d5 [2] e7 d9 [2] eb d3 [2] fc d8 [2] e7 96 [2] da }

  condition:
    any of them
}