rule TTP_XOR_MULT_DOSStub_7abb {
  strings:
    $key_7abb = { 2e d3 [2] 5a cb [2] 1d c9 [2] 5a d8 [2] 14 d4 [2] 18 de [2] 0f d5 [2] 14 9b [2] 29 }

  condition:
    any of them
}