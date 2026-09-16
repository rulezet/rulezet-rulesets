rule TTP_XOR_QUAD_CurrentVersionRun_b4df {
  strings:
    $key_b4df = { e7 b0 [2] c3 be [2] e8 92 [2] c6 b0 [2] d2 ab [2] dd b1 [2] c3 ac [2] c1 ad [2] da ab [2] c6 ac [2] da 83 }

  condition:
    any of them
}