rule TTP_XOR_MULT_DOSStub_b846 {
  strings:
    $key_b846 = { ec 2e [2] 98 36 [2] df 34 [2] 98 25 [2] d6 29 [2] da 23 [2] cd 28 [2] d6 66 [2] eb }

  condition:
    any of them
}