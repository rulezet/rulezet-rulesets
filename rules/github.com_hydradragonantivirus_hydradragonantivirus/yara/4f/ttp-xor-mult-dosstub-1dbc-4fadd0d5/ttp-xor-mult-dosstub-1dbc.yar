rule TTP_XOR_MULT_DOSStub_1dbc {
  strings:
    $key_1dbc = { 49 d4 [2] 3d cc [2] 7a ce [2] 3d df [2] 73 d3 [2] 7f d9 [2] 68 d2 [2] 73 9c [2] 4e }

  condition:
    any of them
}