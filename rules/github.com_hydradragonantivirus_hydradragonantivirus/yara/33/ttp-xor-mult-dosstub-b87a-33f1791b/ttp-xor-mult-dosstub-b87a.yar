rule TTP_XOR_MULT_DOSStub_b87a {
  strings:
    $key_b87a = { ec 12 [2] 98 0a [2] df 08 [2] 98 19 [2] d6 15 [2] da 1f [2] cd 14 [2] d6 5a [2] eb }

  condition:
    any of them
}