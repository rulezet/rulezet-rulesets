rule TTP_XOR_MULT_DOSStub_34bb {
  strings:
    $key_34bb = { 60 d3 [2] 14 cb [2] 53 c9 [2] 14 d8 [2] 5a d4 [2] 56 de [2] 41 d5 [2] 5a 9b [2] 67 }

  condition:
    any of them
}