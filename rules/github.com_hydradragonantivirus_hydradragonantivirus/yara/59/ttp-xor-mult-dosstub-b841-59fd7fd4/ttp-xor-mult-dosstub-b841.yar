rule TTP_XOR_MULT_DOSStub_b841 {
  strings:
    $key_b841 = { ec 29 [2] 98 31 [2] df 33 [2] 98 22 [2] d6 2e [2] da 24 [2] cd 2f [2] d6 61 [2] eb }

  condition:
    any of them
}