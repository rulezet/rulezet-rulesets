rule TTP_XOR_MULT_DOSStub_b8ea {
  strings:
    $key_b8ea = { ec 82 [2] 98 9a [2] df 98 [2] 98 89 [2] d6 85 [2] da 8f [2] cd 84 [2] d6 ca [2] eb }

  condition:
    any of them
}