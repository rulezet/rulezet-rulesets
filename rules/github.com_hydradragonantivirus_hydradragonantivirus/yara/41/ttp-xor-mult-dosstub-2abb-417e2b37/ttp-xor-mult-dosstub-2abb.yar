rule TTP_XOR_MULT_DOSStub_2abb {
  strings:
    $key_2abb = { 7e d3 [2] 0a cb [2] 4d c9 [2] 0a d8 [2] 44 d4 [2] 48 de [2] 5f d5 [2] 44 9b [2] 79 }

  condition:
    any of them
}