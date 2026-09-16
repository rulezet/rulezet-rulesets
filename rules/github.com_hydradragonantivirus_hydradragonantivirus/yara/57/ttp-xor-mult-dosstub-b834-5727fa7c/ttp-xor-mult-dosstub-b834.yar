rule TTP_XOR_MULT_DOSStub_b834 {
  strings:
    $key_b834 = { ec 5c [2] 98 44 [2] df 46 [2] 98 57 [2] d6 5b [2] da 51 [2] cd 5a [2] d6 14 [2] eb }

  condition:
    any of them
}