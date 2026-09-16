rule TTP_XOR_MULT_DOSStub_7bbc {
  strings:
    $key_7bbc = { 2f d4 [2] 5b cc [2] 1c ce [2] 5b df [2] 15 d3 [2] 19 d9 [2] 0e d2 [2] 15 9c [2] 28 }

  condition:
    any of them
}