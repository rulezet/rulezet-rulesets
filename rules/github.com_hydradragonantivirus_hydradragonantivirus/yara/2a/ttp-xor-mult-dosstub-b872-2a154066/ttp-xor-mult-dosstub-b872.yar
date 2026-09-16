rule TTP_XOR_MULT_DOSStub_b872 {
  strings:
    $key_b872 = { ec 1a [2] 98 02 [2] df 00 [2] 98 11 [2] d6 1d [2] da 17 [2] cd 1c [2] d6 52 [2] eb }

  condition:
    any of them
}