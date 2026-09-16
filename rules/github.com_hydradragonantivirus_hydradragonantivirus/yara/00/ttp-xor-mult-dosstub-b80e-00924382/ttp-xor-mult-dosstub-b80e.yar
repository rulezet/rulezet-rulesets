rule TTP_XOR_MULT_DOSStub_b80e {
  strings:
    $key_b80e = { ec 66 [2] 98 7e [2] df 7c [2] 98 6d [2] d6 61 [2] da 6b [2] cd 60 [2] d6 2e [2] eb }

  condition:
    any of them
}