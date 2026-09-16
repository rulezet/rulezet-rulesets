rule TTP_XOR_MULT_DOSStub_d8bc {
  strings:
    $key_d8bc = { 8c d4 [2] f8 cc [2] bf ce [2] f8 df [2] b6 d3 [2] ba d9 [2] ad d2 [2] b6 9c [2] 8b }

  condition:
    any of them
}