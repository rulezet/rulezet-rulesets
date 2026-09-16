rule TTP_XOR_MULT_DOSStub_89ba {
  strings:
    $key_89ba = { dd d2 [2] a9 ca [2] ee c8 [2] a9 d9 [2] e7 d5 [2] eb df [2] fc d4 [2] e7 9a [2] da }

  condition:
    any of them
}