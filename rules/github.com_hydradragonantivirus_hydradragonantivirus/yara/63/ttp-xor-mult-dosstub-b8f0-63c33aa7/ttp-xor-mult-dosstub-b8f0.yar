rule TTP_XOR_MULT_DOSStub_b8f0 {
  strings:
    $key_b8f0 = { ec 98 [2] 98 80 [2] df 82 [2] 98 93 [2] d6 9f [2] da 95 [2] cd 9e [2] d6 d0 [2] eb }

  condition:
    any of them
}