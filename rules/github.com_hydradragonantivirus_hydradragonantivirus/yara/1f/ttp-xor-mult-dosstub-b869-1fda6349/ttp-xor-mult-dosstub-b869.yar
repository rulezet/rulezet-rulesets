rule TTP_XOR_MULT_DOSStub_b869 {
  strings:
    $key_b869 = { ec 01 [2] 98 19 [2] df 1b [2] 98 0a [2] d6 06 [2] da 0c [2] cd 07 [2] d6 49 [2] eb }

  condition:
    any of them
}