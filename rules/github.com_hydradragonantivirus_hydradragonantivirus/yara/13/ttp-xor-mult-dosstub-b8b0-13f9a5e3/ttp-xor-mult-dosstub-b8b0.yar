rule TTP_XOR_MULT_DOSStub_b8b0 {
  strings:
    $key_b8b0 = { ec d8 [2] 98 c0 [2] df c2 [2] 98 d3 [2] d6 df [2] da d5 [2] cd de [2] d6 90 [2] eb }

  condition:
    any of them
}