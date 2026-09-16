rule TTP_XOR_MULT_DOSStub_b840 {
  strings:
    $key_b840 = { ec 28 [2] 98 30 [2] df 32 [2] 98 23 [2] d6 2f [2] da 25 [2] cd 2e [2] d6 60 [2] eb }

  condition:
    any of them
}