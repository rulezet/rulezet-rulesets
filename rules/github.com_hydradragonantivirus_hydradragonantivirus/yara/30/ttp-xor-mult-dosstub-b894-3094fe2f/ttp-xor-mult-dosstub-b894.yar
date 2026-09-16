rule TTP_XOR_MULT_DOSStub_b894 {
  strings:
    $key_b894 = { ec fc [2] 98 e4 [2] df e6 [2] 98 f7 [2] d6 fb [2] da f1 [2] cd fa [2] d6 b4 [2] eb }

  condition:
    any of them
}