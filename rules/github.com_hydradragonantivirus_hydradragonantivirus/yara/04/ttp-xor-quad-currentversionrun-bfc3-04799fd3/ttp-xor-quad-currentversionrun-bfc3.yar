rule TTP_XOR_QUAD_CurrentVersionRun_bfc3 {
  strings:
    $key_bfc3 = { ec ac [2] c8 a2 [2] e3 8e [2] cd ac [2] d9 b7 [2] d6 ad [2] c8 b0 [2] ca b1 [2] d1 b7 [2] cd b0 [2] d1 9f }

  condition:
    any of them
}