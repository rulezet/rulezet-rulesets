rule TTP_XOR_QUAD_CurrentVersionRun_62df {
  strings:
    $key_62df = { 31 b0 [2] 15 be [2] 3e 92 [2] 10 b0 [2] 04 ab [2] 0b b1 [2] 15 ac [2] 17 ad [2] 0c ab [2] 10 ac [2] 0c 83 }

  condition:
    any of them
}