rule TTP_XOR_MULT_DOSStub_b8b7 {
  strings:
    $key_b8b7 = { ec df [2] 98 c7 [2] df c5 [2] 98 d4 [2] d6 d8 [2] da d2 [2] cd d9 [2] d6 97 [2] eb }

  condition:
    any of them
}