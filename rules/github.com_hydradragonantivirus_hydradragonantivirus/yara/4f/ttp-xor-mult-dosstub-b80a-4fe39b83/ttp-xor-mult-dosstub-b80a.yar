rule TTP_XOR_MULT_DOSStub_b80a {
  strings:
    $key_b80a = { ec 62 [2] 98 7a [2] df 78 [2] 98 69 [2] d6 65 [2] da 6f [2] cd 64 [2] d6 2a [2] eb }

  condition:
    any of them
}