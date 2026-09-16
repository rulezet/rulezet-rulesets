rule TTP_XOR_MULT_DOSStub_b8e9 {
  strings:
    $key_b8e9 = { ec 81 [2] 98 99 [2] df 9b [2] 98 8a [2] d6 86 [2] da 8c [2] cd 87 [2] d6 c9 [2] eb }

  condition:
    any of them
}