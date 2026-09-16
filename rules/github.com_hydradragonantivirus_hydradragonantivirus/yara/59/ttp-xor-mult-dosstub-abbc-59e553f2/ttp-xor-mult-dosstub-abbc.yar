rule TTP_XOR_MULT_DOSStub_abbc {
  strings:
    $key_abbc = { ff d4 [2] 8b cc [2] cc ce [2] 8b df [2] c5 d3 [2] c9 d9 [2] de d2 [2] c5 9c [2] f8 }

  condition:
    any of them
}