rule TTP_XOR_MULT_DOSStub_b870 {
  strings:
    $key_b870 = { ec 18 [2] 98 00 [2] df 02 [2] 98 13 [2] d6 1f [2] da 15 [2] cd 1e [2] d6 50 [2] eb }

  condition:
    any of them
}