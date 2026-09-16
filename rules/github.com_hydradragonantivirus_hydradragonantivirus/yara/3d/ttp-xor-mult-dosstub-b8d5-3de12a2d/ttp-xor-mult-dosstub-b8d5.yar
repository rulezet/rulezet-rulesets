rule TTP_XOR_MULT_DOSStub_b8d5 {
  strings:
    $key_b8d5 = { ec bd [2] 98 a5 [2] df a7 [2] 98 b6 [2] d6 ba [2] da b0 [2] cd bb [2] d6 f5 [2] eb }

  condition:
    any of them
}