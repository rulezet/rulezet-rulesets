rule TTP_XOR_MULT_DOSStub_b849 {
  strings:
    $key_b849 = { ec 21 [2] 98 39 [2] df 3b [2] 98 2a [2] d6 26 [2] da 2c [2] cd 27 [2] d6 69 [2] eb }

  condition:
    any of them
}