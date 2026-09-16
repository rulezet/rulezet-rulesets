rule TTP_XOR_MULT_DOSStub_b8c0 {
  strings:
    $key_b8c0 = { ec a8 [2] 98 b0 [2] df b2 [2] 98 a3 [2] d6 af [2] da a5 [2] cd ae [2] d6 e0 [2] eb }

  condition:
    any of them
}