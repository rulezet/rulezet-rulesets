rule TTP_XOR_MULT_DOSStub_b878 {
  strings:
    $key_b878 = { ec 10 [2] 98 08 [2] df 0a [2] 98 1b [2] d6 17 [2] da 1d [2] cd 16 [2] d6 58 [2] eb }

  condition:
    any of them
}