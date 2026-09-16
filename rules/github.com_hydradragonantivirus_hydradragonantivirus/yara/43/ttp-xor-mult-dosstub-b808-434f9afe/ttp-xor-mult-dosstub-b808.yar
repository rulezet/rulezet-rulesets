rule TTP_XOR_MULT_DOSStub_b808 {
  strings:
    $key_b808 = { ec 60 [2] 98 78 [2] df 7a [2] 98 6b [2] d6 67 [2] da 6d [2] cd 66 [2] d6 28 [2] eb }

  condition:
    any of them
}