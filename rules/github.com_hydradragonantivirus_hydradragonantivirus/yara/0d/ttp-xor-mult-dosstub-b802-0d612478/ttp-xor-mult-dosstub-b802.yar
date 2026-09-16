rule TTP_XOR_MULT_DOSStub_b802 {
  strings:
    $key_b802 = { ec 6a [2] 98 72 [2] df 70 [2] 98 61 [2] d6 6d [2] da 67 [2] cd 6c [2] d6 22 [2] eb }

  condition:
    any of them
}