rule TTP_XOR_MULT_DOSStub_b825 {
  strings:
    $key_b825 = { ec 4d [2] 98 55 [2] df 57 [2] 98 46 [2] d6 4a [2] da 40 [2] cd 4b [2] d6 05 [2] eb }

  condition:
    any of them
}