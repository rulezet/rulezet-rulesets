rule TTP_XOR_MULT_DOSStub_7bbb {
  strings:
    $key_7bbb = { 2f d3 [2] 5b cb [2] 1c c9 [2] 5b d8 [2] 15 d4 [2] 19 de [2] 0e d5 [2] 15 9b [2] 28 }

  condition:
    any of them
}