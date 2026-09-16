rule TTP_XOR_MULT_DOSStub_b804 {
  strings:
    $key_b804 = { ec 6c [2] 98 74 [2] df 76 [2] 98 67 [2] d6 6b [2] da 61 [2] cd 6a [2] d6 24 [2] eb }

  condition:
    any of them
}