rule TTP_XOR_MULT_DOSStub_6dbc {
  strings:
    $key_6dbc = { 39 d4 [2] 4d cc [2] 0a ce [2] 4d df [2] 03 d3 [2] 0f d9 [2] 18 d2 [2] 03 9c [2] 3e }

  condition:
    any of them
}