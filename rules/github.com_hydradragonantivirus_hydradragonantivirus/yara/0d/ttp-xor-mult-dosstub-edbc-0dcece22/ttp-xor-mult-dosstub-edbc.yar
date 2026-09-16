rule TTP_XOR_MULT_DOSStub_edbc {
  strings:
    $key_edbc = { b9 d4 [2] cd cc [2] 8a ce [2] cd df [2] 83 d3 [2] 8f d9 [2] 98 d2 [2] 83 9c [2] be }

  condition:
    any of them
}