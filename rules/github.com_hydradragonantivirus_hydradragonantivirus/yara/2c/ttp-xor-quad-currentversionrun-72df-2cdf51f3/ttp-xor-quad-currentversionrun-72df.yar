rule TTP_XOR_QUAD_CurrentVersionRun_72df {
  strings:
    $key_72df = { 21 b0 [2] 05 be [2] 2e 92 [2] 00 b0 [2] 14 ab [2] 1b b1 [2] 05 ac [2] 07 ad [2] 1c ab [2] 00 ac [2] 1c 83 }

  condition:
    any of them
}