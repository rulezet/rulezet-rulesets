rule TTP_XOR_MULT_DOSStub_7abc {
  strings:
    $key_7abc = { 2e d4 [2] 5a cc [2] 1d ce [2] 5a df [2] 14 d3 [2] 18 d9 [2] 0f d2 [2] 14 9c [2] 29 }

  condition:
    any of them
}