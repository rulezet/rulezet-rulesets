rule TTP_XOR_MULT_DOSStub_1abc {
  strings:
    $key_1abc = { 4e d4 [2] 3a cc [2] 7d ce [2] 3a df [2] 74 d3 [2] 78 d9 [2] 6f d2 [2] 74 9c [2] 49 }

  condition:
    any of them
}