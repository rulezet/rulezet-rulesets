rule TTP_XOR_QUAD_CurrentVersionRun_21df {
  strings:
    $key_21df = { 72 b0 [2] 56 be [2] 7d 92 [2] 53 b0 [2] 47 ab [2] 48 b1 [2] 56 ac [2] 54 ad [2] 4f ab [2] 53 ac [2] 4f 83 }

  condition:
    any of them
}