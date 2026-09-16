rule TTP_XOR_MULT_DOSStub_b89e {
  strings:
    $key_b89e = { ec f6 [2] 98 ee [2] df ec [2] 98 fd [2] d6 f1 [2] da fb [2] cd f0 [2] d6 be [2] eb }

  condition:
    any of them
}