rule TTP_XOR_MULT_DOSStub_6bbb {
  strings:
    $key_6bbb = { 3f d3 [2] 4b cb [2] 0c c9 [2] 4b d8 [2] 05 d4 [2] 09 de [2] 1e d5 [2] 05 9b [2] 38 }

  condition:
    any of them
}