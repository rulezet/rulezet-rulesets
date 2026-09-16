rule TTP_XOR_MULT_DOSStub_b86e {
  strings:
    $key_b86e = { ec 06 [2] 98 1e [2] df 1c [2] 98 0d [2] d6 01 [2] da 0b [2] cd 00 [2] d6 4e [2] eb }

  condition:
    any of them
}