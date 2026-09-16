rule TTP_XOR_MULT_DOSStub_b85b {
  strings:
    $key_b85b = { ec 33 [2] 98 2b [2] df 29 [2] 98 38 [2] d6 34 [2] da 3e [2] cd 35 [2] d6 7b [2] eb }

  condition:
    any of them
}