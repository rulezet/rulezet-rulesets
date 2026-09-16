rule TTP_XOR_MULT_DOSStub_d8bb {
  strings:
    $key_d8bb = { 8c d3 [2] f8 cb [2] bf c9 [2] f8 d8 [2] b6 d4 [2] ba de [2] ad d5 [2] b6 9b [2] 8b }

  condition:
    any of them
}