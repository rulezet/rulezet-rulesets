rule TTP_XOR_MULT_DOSStub_b8d4 {
  strings:
    $key_b8d4 = { ec bc [2] 98 a4 [2] df a6 [2] 98 b7 [2] d6 bb [2] da b1 [2] cd ba [2] d6 f4 [2] eb }

  condition:
    any of them
}