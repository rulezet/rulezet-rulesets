rule TTP_XOR_QUAD_CurrentVersionRun_56df {
  strings:
    $key_56df = { 05 b0 [2] 21 be [2] 0a 92 [2] 24 b0 [2] 30 ab [2] 3f b1 [2] 21 ac [2] 23 ad [2] 38 ab [2] 24 ac [2] 38 83 }

  condition:
    any of them
}