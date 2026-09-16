rule TTP_XOR_MULT_DOSStub_b833 {
  strings:
    $key_b833 = { ec 5b [2] 98 43 [2] df 41 [2] 98 50 [2] d6 5c [2] da 56 [2] cd 5d [2] d6 13 [2] eb }

  condition:
    any of them
}