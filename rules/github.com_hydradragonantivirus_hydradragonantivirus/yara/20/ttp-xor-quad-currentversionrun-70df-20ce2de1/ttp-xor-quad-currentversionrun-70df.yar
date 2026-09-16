rule TTP_XOR_QUAD_CurrentVersionRun_70df {
  strings:
    $key_70df = { 23 b0 [2] 07 be [2] 2c 92 [2] 02 b0 [2] 16 ab [2] 19 b1 [2] 07 ac [2] 05 ad [2] 1e ab [2] 02 ac [2] 1e 83 }

  condition:
    any of them
}