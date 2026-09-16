rule TTP_XOR_MULT_DOSStub_b81f {
  strings:
    $key_b81f = { ec 77 [2] 98 6f [2] df 6d [2] 98 7c [2] d6 70 [2] da 7a [2] cd 71 [2] d6 3f [2] eb }

  condition:
    any of them
}