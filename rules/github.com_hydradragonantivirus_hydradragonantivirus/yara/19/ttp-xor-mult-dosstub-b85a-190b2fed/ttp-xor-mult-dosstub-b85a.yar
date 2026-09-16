rule TTP_XOR_MULT_DOSStub_b85a {
  strings:
    $key_b85a = { ec 32 [2] 98 2a [2] df 28 [2] 98 39 [2] d6 35 [2] da 3f [2] cd 34 [2] d6 7a [2] eb }

  condition:
    any of them
}