rule TTP_XOR_MULT_DOSStub_b8ef {
  strings:
    $key_b8ef = { ec 87 [2] 98 9f [2] df 9d [2] 98 8c [2] d6 80 [2] da 8a [2] cd 81 [2] d6 cf [2] eb }

  condition:
    any of them
}