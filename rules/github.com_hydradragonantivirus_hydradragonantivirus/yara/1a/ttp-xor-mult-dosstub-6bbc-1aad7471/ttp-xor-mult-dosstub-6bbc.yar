rule TTP_XOR_MULT_DOSStub_6bbc {
  strings:
    $key_6bbc = { 3f d4 [2] 4b cc [2] 0c ce [2] 4b df [2] 05 d3 [2] 09 d9 [2] 1e d2 [2] 05 9c [2] 38 }

  condition:
    any of them
}