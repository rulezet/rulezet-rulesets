rule TTP_XOR_MULT_DOSStub_b853 {
  strings:
    $key_b853 = { ec 3b [2] 98 23 [2] df 21 [2] 98 30 [2] d6 3c [2] da 36 [2] cd 3d [2] d6 73 [2] eb }

  condition:
    any of them
}