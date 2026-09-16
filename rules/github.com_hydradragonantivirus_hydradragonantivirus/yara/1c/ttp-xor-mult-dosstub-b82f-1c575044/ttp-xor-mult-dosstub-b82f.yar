rule TTP_XOR_MULT_DOSStub_b82f {
  strings:
    $key_b82f = { ec 47 [2] 98 5f [2] df 5d [2] 98 4c [2] d6 40 [2] da 4a [2] cd 41 [2] d6 0f [2] eb }

  condition:
    any of them
}