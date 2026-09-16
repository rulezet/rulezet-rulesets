rule TTP_XOR_MULT_DOSStub_b8ac {
  strings:
    $key_b8ac = { ec c4 [2] 98 dc [2] df de [2] 98 cf [2] d6 c3 [2] da c9 [2] cd c2 [2] d6 8c [2] eb }

  condition:
    any of them
}