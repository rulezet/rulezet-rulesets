rule TTP_XOR_MULT_DOSStub_b806 {
  strings:
    $key_b806 = { ec 6e [2] 98 76 [2] df 74 [2] 98 65 [2] d6 69 [2] da 63 [2] cd 68 [2] d6 26 [2] eb }

  condition:
    any of them
}