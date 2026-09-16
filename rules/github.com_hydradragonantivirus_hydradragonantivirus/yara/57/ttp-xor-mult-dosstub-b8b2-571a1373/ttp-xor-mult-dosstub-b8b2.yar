rule TTP_XOR_MULT_DOSStub_b8b2 {
  strings:
    $key_b8b2 = { ec da [2] 98 c2 [2] df c0 [2] 98 d1 [2] d6 dd [2] da d7 [2] cd dc [2] d6 92 [2] eb }

  condition:
    any of them
}