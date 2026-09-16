rule TTP_XOR_MULT_DOSStub_b845 {
  strings:
    $key_b845 = { ec 2d [2] 98 35 [2] df 37 [2] 98 26 [2] d6 2a [2] da 20 [2] cd 2b [2] d6 65 [2] eb }

  condition:
    any of them
}