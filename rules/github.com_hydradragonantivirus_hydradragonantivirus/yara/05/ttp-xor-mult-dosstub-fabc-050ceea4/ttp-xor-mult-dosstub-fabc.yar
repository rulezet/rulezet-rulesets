rule TTP_XOR_MULT_DOSStub_fabc {
  strings:
    $key_fabc = { ae d4 [2] da cc [2] 9d ce [2] da df [2] 94 d3 [2] 98 d9 [2] 8f d2 [2] 94 9c [2] a9 }

  condition:
    any of them
}