rule TTP_XOR_MULT_DOSStub_b874 {
  strings:
    $key_b874 = { ec 1c [2] 98 04 [2] df 06 [2] 98 17 [2] d6 1b [2] da 11 [2] cd 1a [2] d6 54 [2] eb }

  condition:
    any of them
}