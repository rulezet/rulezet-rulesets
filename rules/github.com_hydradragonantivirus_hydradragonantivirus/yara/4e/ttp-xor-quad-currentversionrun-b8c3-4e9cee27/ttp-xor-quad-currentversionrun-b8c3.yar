rule TTP_XOR_QUAD_CurrentVersionRun_b8c3 {
  strings:
    $key_b8c3 = { eb ac [2] cf a2 [2] e4 8e [2] ca ac [2] de b7 [2] d1 ad [2] cf b0 [2] cd b1 [2] d6 b7 [2] ca b0 [2] d6 9f }

  condition:
    any of them
}