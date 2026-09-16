rule TTP_XOR_QUAD_CurrentVersionRun_15df {
  strings:
    $key_15df = { 46 b0 [2] 62 be [2] 49 92 [2] 67 b0 [2] 73 ab [2] 7c b1 [2] 62 ac [2] 60 ad [2] 7b ab [2] 67 ac [2] 7b 83 }

  condition:
    any of them
}