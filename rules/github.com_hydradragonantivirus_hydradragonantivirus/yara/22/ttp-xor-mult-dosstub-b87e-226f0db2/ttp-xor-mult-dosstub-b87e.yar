rule TTP_XOR_MULT_DOSStub_b87e {
  strings:
    $key_b87e = { ec 16 [2] 98 0e [2] df 0c [2] 98 1d [2] d6 11 [2] da 1b [2] cd 10 [2] d6 5e [2] eb }

  condition:
    any of them
}