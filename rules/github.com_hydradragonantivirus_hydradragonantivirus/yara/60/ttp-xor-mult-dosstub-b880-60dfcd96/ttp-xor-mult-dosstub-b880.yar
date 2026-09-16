rule TTP_XOR_MULT_DOSStub_b880 {
  strings:
    $key_b880 = { ec e8 [2] 98 f0 [2] df f2 [2] 98 e3 [2] d6 ef [2] da e5 [2] cd ee [2] d6 a0 [2] eb }

  condition:
    any of them
}