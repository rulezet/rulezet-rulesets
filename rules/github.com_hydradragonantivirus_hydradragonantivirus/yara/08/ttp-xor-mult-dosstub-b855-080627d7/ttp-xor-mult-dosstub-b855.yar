rule TTP_XOR_MULT_DOSStub_b855 {
  strings:
    $key_b855 = { ec 3d [2] 98 25 [2] df 27 [2] 98 36 [2] d6 3a [2] da 30 [2] cd 3b [2] d6 75 [2] eb }

  condition:
    any of them
}