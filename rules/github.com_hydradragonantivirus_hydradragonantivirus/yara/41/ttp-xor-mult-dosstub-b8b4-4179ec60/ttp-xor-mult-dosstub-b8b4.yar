rule TTP_XOR_MULT_DOSStub_b8b4 {
  strings:
    $key_b8b4 = { ec dc [2] 98 c4 [2] df c6 [2] 98 d7 [2] d6 db [2] da d1 [2] cd da [2] d6 94 [2] eb }

  condition:
    any of them
}