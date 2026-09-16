rule TTP_XOR_MULT_DOSStub_b871 {
  strings:
    $key_b871 = { ec 19 [2] 98 01 [2] df 03 [2] 98 12 [2] d6 1e [2] da 14 [2] cd 1f [2] d6 51 [2] eb }

  condition:
    any of them
}