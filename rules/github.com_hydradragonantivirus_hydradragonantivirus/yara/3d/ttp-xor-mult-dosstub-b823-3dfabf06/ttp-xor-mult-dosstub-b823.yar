rule TTP_XOR_MULT_DOSStub_b823 {
  strings:
    $key_b823 = { ec 4b [2] 98 53 [2] df 51 [2] 98 40 [2] d6 4c [2] da 46 [2] cd 4d [2] d6 03 [2] eb }

  condition:
    any of them
}