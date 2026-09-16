rule TTP_XOR_MULT_DOSStub_b83a {
  strings:
    $key_b83a = { ec 52 [2] 98 4a [2] df 48 [2] 98 59 [2] d6 55 [2] da 5f [2] cd 54 [2] d6 1a [2] eb }

  condition:
    any of them
}