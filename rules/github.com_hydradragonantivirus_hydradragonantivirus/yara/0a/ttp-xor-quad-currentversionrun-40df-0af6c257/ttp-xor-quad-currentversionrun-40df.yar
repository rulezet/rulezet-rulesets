rule TTP_XOR_QUAD_CurrentVersionRun_40df {
  strings:
    $key_40df = { 13 b0 [2] 37 be [2] 1c 92 [2] 32 b0 [2] 26 ab [2] 29 b1 [2] 37 ac [2] 35 ad [2] 2e ab [2] 32 ac [2] 2e 83 }

  condition:
    any of them
}