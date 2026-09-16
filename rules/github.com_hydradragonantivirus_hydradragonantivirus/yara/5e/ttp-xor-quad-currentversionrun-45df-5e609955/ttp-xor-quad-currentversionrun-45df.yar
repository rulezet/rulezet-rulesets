rule TTP_XOR_QUAD_CurrentVersionRun_45df {
  strings:
    $key_45df = { 16 b0 [2] 32 be [2] 19 92 [2] 37 b0 [2] 23 ab [2] 2c b1 [2] 32 ac [2] 30 ad [2] 2b ab [2] 37 ac [2] 2b 83 }

  condition:
    any of them
}