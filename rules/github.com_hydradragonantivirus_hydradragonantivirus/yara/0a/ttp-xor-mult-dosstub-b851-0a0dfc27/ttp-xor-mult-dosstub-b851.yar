rule TTP_XOR_MULT_DOSStub_b851 {
  strings:
    $key_b851 = { ec 39 [2] 98 21 [2] df 23 [2] 98 32 [2] d6 3e [2] da 34 [2] cd 3f [2] d6 71 [2] eb }

  condition:
    any of them
}