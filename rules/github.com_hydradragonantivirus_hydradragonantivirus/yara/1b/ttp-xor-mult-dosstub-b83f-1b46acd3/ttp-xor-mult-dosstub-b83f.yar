rule TTP_XOR_MULT_DOSStub_b83f {
  strings:
    $key_b83f = { ec 57 [2] 98 4f [2] df 4d [2] 98 5c [2] d6 50 [2] da 5a [2] cd 51 [2] d6 1f [2] eb }

  condition:
    any of them
}