rule TTP_XOR_QUAD_CurrentVersionRun_07df {
  strings:
    $key_07df = { 54 b0 [2] 70 be [2] 5b 92 [2] 75 b0 [2] 61 ab [2] 6e b1 [2] 70 ac [2] 72 ad [2] 69 ab [2] 75 ac [2] 69 83 }

  condition:
    any of them
}