rule TTP_XOR_MULT_DOSStub_b832 {
  strings:
    $key_b832 = { ec 5a [2] 98 42 [2] df 40 [2] 98 51 [2] d6 5d [2] da 57 [2] cd 5c [2] d6 12 [2] eb }

  condition:
    any of them
}