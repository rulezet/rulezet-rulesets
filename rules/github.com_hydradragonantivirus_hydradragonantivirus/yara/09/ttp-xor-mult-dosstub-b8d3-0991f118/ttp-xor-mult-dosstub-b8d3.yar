rule TTP_XOR_MULT_DOSStub_b8d3 {
  strings:
    $key_b8d3 = { ec bb [2] 98 a3 [2] df a1 [2] 98 b0 [2] d6 bc [2] da b6 [2] cd bd [2] d6 f3 [2] eb }

  condition:
    any of them
}