rule TTP_XOR_QUAD_CurrentVersionRun_74df {
  strings:
    $key_74df = { 27 b0 [2] 03 be [2] 28 92 [2] 06 b0 [2] 12 ab [2] 1d b1 [2] 03 ac [2] 01 ad [2] 1a ab [2] 06 ac [2] 1a 83 }

  condition:
    any of them
}