rule TTP_XOR_MULT_DOSStub_b805 {
  strings:
    $key_b805 = { ec 6d [2] 98 75 [2] df 77 [2] 98 66 [2] d6 6a [2] da 60 [2] cd 6b [2] d6 25 [2] eb }

  condition:
    any of them
}