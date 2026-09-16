rule TTP_XOR_MULT_DOSStub_b8b1 {
  strings:
    $key_b8b1 = { ec d9 [2] 98 c1 [2] df c3 [2] 98 d2 [2] d6 de [2] da d4 [2] cd df [2] d6 91 [2] eb }

  condition:
    any of them
}