rule TTP_XOR_MULT_DOSStub_4bbb {
  strings:
    $key_4bbb = { 1f d3 [2] 6b cb [2] 2c c9 [2] 6b d8 [2] 25 d4 [2] 29 de [2] 3e d5 [2] 25 9b [2] 18 }

  condition:
    any of them
}