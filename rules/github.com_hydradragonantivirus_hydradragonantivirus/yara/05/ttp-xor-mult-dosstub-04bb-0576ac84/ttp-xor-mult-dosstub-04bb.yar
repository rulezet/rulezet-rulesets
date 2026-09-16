rule TTP_XOR_MULT_DOSStub_04bb {
  strings:
    $key_04bb = { 50 d3 [2] 24 cb [2] 63 c9 [2] 24 d8 [2] 6a d4 [2] 66 de [2] 71 d5 [2] 6a 9b [2] 57 }

  condition:
    any of them
}