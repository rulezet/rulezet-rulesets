rule TTP_XOR_MULT_DOSStub_b8ee {
  strings:
    $key_b8ee = { ec 86 [2] 98 9e [2] df 9c [2] 98 8d [2] d6 81 [2] da 8b [2] cd 80 [2] d6 ce [2] eb }

  condition:
    any of them
}