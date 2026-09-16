rule TTP_XOR_MULT_DOSStub_b8bf {
  strings:
    $key_b8bf = { ec d7 [2] 98 cf [2] df cd [2] 98 dc [2] d6 d0 [2] da da [2] cd d1 [2] d6 9f [2] eb }

  condition:
    any of them
}