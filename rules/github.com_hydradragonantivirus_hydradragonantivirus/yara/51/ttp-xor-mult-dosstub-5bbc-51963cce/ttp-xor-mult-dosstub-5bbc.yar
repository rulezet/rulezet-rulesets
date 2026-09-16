rule TTP_XOR_MULT_DOSStub_5bbc {
  strings:
    $key_5bbc = { 0f d4 [2] 7b cc [2] 3c ce [2] 7b df [2] 35 d3 [2] 39 d9 [2] 2e d2 [2] 35 9c [2] 08 }

  condition:
    any of them
}