rule TTP_XOR_MULT_DOSStub_29bb {
  strings:
    $key_29bb = { 7d d3 [2] 09 cb [2] 4e c9 [2] 09 d8 [2] 47 d4 [2] 4b de [2] 5c d5 [2] 47 9b [2] 7a }

  condition:
    any of them
}