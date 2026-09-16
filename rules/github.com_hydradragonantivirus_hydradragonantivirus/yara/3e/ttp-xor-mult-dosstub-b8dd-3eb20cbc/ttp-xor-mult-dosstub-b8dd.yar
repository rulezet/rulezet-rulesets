rule TTP_XOR_MULT_DOSStub_b8dd {
  strings:
    $key_b8dd = { ec b5 [2] 98 ad [2] df af [2] 98 be [2] d6 b2 [2] da b8 [2] cd b3 [2] d6 fd [2] eb }

  condition:
    any of them
}