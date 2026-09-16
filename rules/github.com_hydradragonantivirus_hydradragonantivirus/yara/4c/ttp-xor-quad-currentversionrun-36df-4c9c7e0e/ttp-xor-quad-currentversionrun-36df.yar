rule TTP_XOR_QUAD_CurrentVersionRun_36df {
  strings:
    $key_36df = { 65 b0 [2] 41 be [2] 6a 92 [2] 44 b0 [2] 50 ab [2] 5f b1 [2] 41 ac [2] 43 ad [2] 58 ab [2] 44 ac [2] 58 83 }

  condition:
    any of them
}