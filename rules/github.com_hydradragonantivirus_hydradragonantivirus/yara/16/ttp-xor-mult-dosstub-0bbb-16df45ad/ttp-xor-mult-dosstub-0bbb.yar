rule TTP_XOR_MULT_DOSStub_0bbb {
  strings:
    $key_0bbb = { 5f d3 [2] 2b cb [2] 6c c9 [2] 2b d8 [2] 65 d4 [2] 69 de [2] 7e d5 [2] 65 9b [2] 58 }

  condition:
    any of them
}