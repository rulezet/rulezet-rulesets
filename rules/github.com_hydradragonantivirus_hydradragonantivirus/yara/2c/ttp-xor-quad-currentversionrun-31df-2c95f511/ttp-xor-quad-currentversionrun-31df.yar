rule TTP_XOR_QUAD_CurrentVersionRun_31df {
  strings:
    $key_31df = { 62 b0 [2] 46 be [2] 6d 92 [2] 43 b0 [2] 57 ab [2] 58 b1 [2] 46 ac [2] 44 ad [2] 5f ab [2] 43 ac [2] 5f 83 }

  condition:
    any of them
}