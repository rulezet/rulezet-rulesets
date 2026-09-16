rule TTP_XOR_MULT_DOSStub_8b84 {
  strings:
    $key_8b84 = { df ec [2] ab f4 [2] ec f6 [2] ab e7 [2] e5 eb [2] e9 e1 [2] fe ea [2] e5 a4 [2] d8 }

  condition:
    any of them
}