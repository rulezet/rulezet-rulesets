rule TTP_XOR_MULT_DOSStub_6abb {
  strings:
    $key_6abb = { 3e d3 [2] 4a cb [2] 0d c9 [2] 4a d8 [2] 04 d4 [2] 08 de [2] 1f d5 [2] 04 9b [2] 39 }

  condition:
    any of them
}