rule TTP_XOR_MULT_DOSStub_1fbb {
  strings:
    $key_1fbb = { 4b d3 [2] 3f cb [2] 78 c9 [2] 3f d8 [2] 71 d4 [2] 7d de [2] 6a d5 [2] 71 9b [2] 4c }

  condition:
    any of them
}