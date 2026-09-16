rule TTP_XOR_MULT_DOSStub_b865 {
  strings:
    $key_b865 = { ec 0d [2] 98 15 [2] df 17 [2] 98 06 [2] d6 0a [2] da 00 [2] cd 0b [2] d6 45 [2] eb }

  condition:
    any of them
}