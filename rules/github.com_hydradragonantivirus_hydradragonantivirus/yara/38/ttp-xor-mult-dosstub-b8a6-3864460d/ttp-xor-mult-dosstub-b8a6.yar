rule TTP_XOR_MULT_DOSStub_b8a6 {
  strings:
    $key_b8a6 = { ec ce [2] 98 d6 [2] df d4 [2] 98 c5 [2] d6 c9 [2] da c3 [2] cd c8 [2] d6 86 [2] eb }

  condition:
    any of them
}