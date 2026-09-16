rule TTP_XOR_MULT_DOSStub_b8bc {
  strings:
    $key_b8bc = { ec d4 [2] 98 cc [2] df ce [2] 98 df [2] d6 d3 [2] da d9 [2] cd d2 [2] d6 9c [2] eb }

  condition:
    any of them
}