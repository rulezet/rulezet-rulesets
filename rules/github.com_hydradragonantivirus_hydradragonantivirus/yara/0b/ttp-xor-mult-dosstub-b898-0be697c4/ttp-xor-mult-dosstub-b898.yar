rule TTP_XOR_MULT_DOSStub_b898 {
  strings:
    $key_b898 = { ec f0 [2] 98 e8 [2] df ea [2] 98 fb [2] d6 f7 [2] da fd [2] cd f6 [2] d6 b8 [2] eb }

  condition:
    any of them
}