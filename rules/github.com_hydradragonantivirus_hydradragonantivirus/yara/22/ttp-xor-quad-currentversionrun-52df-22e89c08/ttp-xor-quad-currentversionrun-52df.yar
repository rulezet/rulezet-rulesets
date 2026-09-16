rule TTP_XOR_QUAD_CurrentVersionRun_52df {
  strings:
    $key_52df = { 01 b0 [2] 25 be [2] 0e 92 [2] 20 b0 [2] 34 ab [2] 3b b1 [2] 25 ac [2] 27 ad [2] 3c ab [2] 20 ac [2] 3c 83 }

  condition:
    any of them
}