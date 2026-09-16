rule TTP_XOR_MULT_DOSStub_b86d {
  strings:
    $key_b86d = { ec 05 [2] 98 1d [2] df 1f [2] 98 0e [2] d6 02 [2] da 08 [2] cd 03 [2] d6 4d [2] eb }

  condition:
    any of them
}