rule TTP_XOR_MULT_DOSStub_b862 {
  strings:
    $key_b862 = { ec 0a [2] 98 12 [2] df 10 [2] 98 01 [2] d6 0d [2] da 07 [2] cd 0c [2] d6 42 [2] eb }

  condition:
    any of them
}