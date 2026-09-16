rule TTP_XOR_MULT_DOSStub_b889 {
  strings:
    $key_b889 = { ec e1 [2] 98 f9 [2] df fb [2] 98 ea [2] d6 e6 [2] da ec [2] cd e7 [2] d6 a9 [2] eb }

  condition:
    any of them
}