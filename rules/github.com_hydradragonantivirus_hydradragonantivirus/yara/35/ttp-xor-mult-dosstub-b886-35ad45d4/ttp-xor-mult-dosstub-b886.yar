rule TTP_XOR_MULT_DOSStub_b886 {
  strings:
    $key_b886 = { ec ee [2] 98 f6 [2] df f4 [2] 98 e5 [2] d6 e9 [2] da e3 [2] cd e8 [2] d6 a6 [2] eb }

  condition:
    any of them
}