rule TTP_XOR_MULT_DOSStub_b83b {
  strings:
    $key_b83b = { ec 53 [2] 98 4b [2] df 49 [2] 98 58 [2] d6 54 [2] da 5e [2] cd 55 [2] d6 1b [2] eb }

  condition:
    any of them
}