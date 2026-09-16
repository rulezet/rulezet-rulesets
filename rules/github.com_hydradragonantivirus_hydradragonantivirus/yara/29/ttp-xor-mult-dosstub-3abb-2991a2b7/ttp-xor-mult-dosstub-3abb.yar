rule TTP_XOR_MULT_DOSStub_3abb {
  strings:
    $key_3abb = { 6e d3 [2] 1a cb [2] 5d c9 [2] 1a d8 [2] 54 d4 [2] 58 de [2] 4f d5 [2] 54 9b [2] 69 }

  condition:
    any of them
}