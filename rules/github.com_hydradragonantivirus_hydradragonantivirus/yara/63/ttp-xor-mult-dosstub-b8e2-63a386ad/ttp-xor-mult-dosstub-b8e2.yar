rule TTP_XOR_MULT_DOSStub_b8e2 {
  strings:
    $key_b8e2 = { ec 8a [2] 98 92 [2] df 90 [2] 98 81 [2] d6 8d [2] da 87 [2] cd 8c [2] d6 c2 [2] eb }

  condition:
    any of them
}