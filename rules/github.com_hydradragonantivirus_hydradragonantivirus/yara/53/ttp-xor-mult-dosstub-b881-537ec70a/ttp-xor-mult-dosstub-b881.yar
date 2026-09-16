rule TTP_XOR_MULT_DOSStub_b881 {
  strings:
    $key_b881 = { ec e9 [2] 98 f1 [2] df f3 [2] 98 e2 [2] d6 ee [2] da e4 [2] cd ef [2] d6 a1 [2] eb }

  condition:
    any of them
}