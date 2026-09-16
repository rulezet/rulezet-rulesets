rule TTP_XOR_MULT_DOSStub_b81b {
  strings:
    $key_b81b = { ec 73 [2] 98 6b [2] df 69 [2] 98 78 [2] d6 74 [2] da 7e [2] cd 75 [2] d6 3b [2] eb }

  condition:
    any of them
}