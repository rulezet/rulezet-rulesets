rule TTP_XOR_MULT_DOSStub_b842 {
  strings:
    $key_b842 = { ec 2a [2] 98 32 [2] df 30 [2] 98 21 [2] d6 2d [2] da 27 [2] cd 2c [2] d6 62 [2] eb }

  condition:
    any of them
}