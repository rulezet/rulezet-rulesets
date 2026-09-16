rule TTP_XOR_QUAD_CurrentVersionRun_d8df {
  strings:
    $key_d8df = { 8b b0 [2] af be [2] 84 92 [2] aa b0 [2] be ab [2] b1 b1 [2] af ac [2] ad ad [2] b6 ab [2] aa ac [2] b6 83 }

  condition:
    any of them
}