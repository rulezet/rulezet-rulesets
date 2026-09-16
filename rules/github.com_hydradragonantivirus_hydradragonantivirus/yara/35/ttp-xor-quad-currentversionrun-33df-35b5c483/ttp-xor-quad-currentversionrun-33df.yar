rule TTP_XOR_QUAD_CurrentVersionRun_33df {
  strings:
    $key_33df = { 60 b0 [2] 44 be [2] 6f 92 [2] 41 b0 [2] 55 ab [2] 5a b1 [2] 44 ac [2] 46 ad [2] 5d ab [2] 41 ac [2] 5d 83 }

  condition:
    any of them
}