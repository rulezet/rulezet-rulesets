rule TTP_XOR_MULT_DOSStub_b8a1 {
  strings:
    $key_b8a1 = { ec c9 [2] 98 d1 [2] df d3 [2] 98 c2 [2] d6 ce [2] da c4 [2] cd cf [2] d6 81 [2] eb }

  condition:
    any of them
}