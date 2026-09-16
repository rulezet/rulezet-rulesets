rule TTP_XOR_MULT_DOSStub_b8f1 {
  strings:
    $key_b8f1 = { ec 99 [2] 98 81 [2] df 83 [2] 98 92 [2] d6 9e [2] da 94 [2] cd 9f [2] d6 d1 [2] eb }

  condition:
    any of them
}