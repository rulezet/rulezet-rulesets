rule TTP_XOR_MULT_DOSStub_2bbc {
  strings:
    $key_2bbc = { 7f d4 [2] 0b cc [2] 4c ce [2] 0b df [2] 45 d3 [2] 49 d9 [2] 5e d2 [2] 45 9c [2] 78 }

  condition:
    any of them
}