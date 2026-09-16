rule TTP_XOR_MULT_DOSStub_b8a0 {
  strings:
    $key_b8a0 = { ec c8 [2] 98 d0 [2] df d2 [2] 98 c3 [2] d6 cf [2] da c5 [2] cd ce [2] d6 80 [2] eb }

  condition:
    any of them
}