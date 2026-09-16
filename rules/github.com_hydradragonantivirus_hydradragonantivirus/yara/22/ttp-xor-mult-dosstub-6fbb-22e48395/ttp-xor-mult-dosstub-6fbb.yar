rule TTP_XOR_MULT_DOSStub_6fbb {
  strings:
    $key_6fbb = { 3b d3 [2] 4f cb [2] 08 c9 [2] 4f d8 [2] 01 d4 [2] 0d de [2] 1a d5 [2] 01 9b [2] 3c }

  condition:
    any of them
}