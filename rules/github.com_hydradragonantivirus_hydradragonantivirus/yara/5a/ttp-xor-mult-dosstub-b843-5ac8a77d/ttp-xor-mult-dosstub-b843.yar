rule TTP_XOR_MULT_DOSStub_b843 {
  strings:
    $key_b843 = { ec 2b [2] 98 33 [2] df 31 [2] 98 20 [2] d6 2c [2] da 26 [2] cd 2d [2] d6 63 [2] eb }

  condition:
    any of them
}