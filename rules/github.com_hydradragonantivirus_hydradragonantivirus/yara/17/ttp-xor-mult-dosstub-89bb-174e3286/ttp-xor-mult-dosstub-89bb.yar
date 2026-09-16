rule TTP_XOR_MULT_DOSStub_89bb {
  strings:
    $key_89bb = { dd d3 [2] a9 cb [2] ee c9 [2] a9 d8 [2] e7 d4 [2] eb de [2] fc d5 [2] e7 9b [2] da }

  condition:
    any of them
}