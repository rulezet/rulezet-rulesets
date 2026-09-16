rule TTP_XOR_MULT_DOSStub_5dbc {
  strings:
    $key_5dbc = { 09 d4 [2] 7d cc [2] 3a ce [2] 7d df [2] 33 d3 [2] 3f d9 [2] 28 d2 [2] 33 9c [2] 0e }

  condition:
    any of them
}