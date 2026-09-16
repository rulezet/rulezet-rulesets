rule TTP_XOR_MULT_DOSStub_b8e5 {
  strings:
    $key_b8e5 = { ec 8d [2] 98 95 [2] df 97 [2] 98 86 [2] d6 8a [2] da 80 [2] cd 8b [2] d6 c5 [2] eb }

  condition:
    any of them
}