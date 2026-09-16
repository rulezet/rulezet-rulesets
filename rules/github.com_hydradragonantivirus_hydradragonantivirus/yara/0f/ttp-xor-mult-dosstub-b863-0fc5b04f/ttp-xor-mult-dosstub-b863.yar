rule TTP_XOR_MULT_DOSStub_b863 {
  strings:
    $key_b863 = { ec 0b [2] 98 13 [2] df 11 [2] 98 00 [2] d6 0c [2] da 06 [2] cd 0d [2] d6 43 [2] eb }

  condition:
    any of them
}