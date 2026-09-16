rule TTP_XOR_QUAD_CurrentVersionRun_20df {
  strings:
    $key_20df = { 73 b0 [2] 57 be [2] 7c 92 [2] 52 b0 [2] 46 ab [2] 49 b1 [2] 57 ac [2] 55 ad [2] 4e ab [2] 52 ac [2] 4e 83 }

  condition:
    any of them
}