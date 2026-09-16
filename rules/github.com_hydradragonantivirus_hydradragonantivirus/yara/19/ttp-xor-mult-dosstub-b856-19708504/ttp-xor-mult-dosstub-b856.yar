rule TTP_XOR_MULT_DOSStub_b856 {
  strings:
    $key_b856 = { ec 3e [2] 98 26 [2] df 24 [2] 98 35 [2] d6 39 [2] da 33 [2] cd 38 [2] d6 76 [2] eb }

  condition:
    any of them
}