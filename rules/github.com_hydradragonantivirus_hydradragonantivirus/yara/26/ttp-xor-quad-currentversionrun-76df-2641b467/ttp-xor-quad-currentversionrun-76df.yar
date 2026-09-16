rule TTP_XOR_QUAD_CurrentVersionRun_76df {
  strings:
    $key_76df = { 25 b0 [2] 01 be [2] 2a 92 [2] 04 b0 [2] 10 ab [2] 1f b1 [2] 01 ac [2] 03 ad [2] 18 ab [2] 04 ac [2] 18 83 }

  condition:
    any of them
}