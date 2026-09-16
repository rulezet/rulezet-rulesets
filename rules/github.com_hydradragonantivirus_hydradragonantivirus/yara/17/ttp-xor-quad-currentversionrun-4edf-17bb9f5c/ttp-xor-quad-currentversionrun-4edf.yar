rule TTP_XOR_QUAD_CurrentVersionRun_4edf {
  strings:
    $key_4edf = { 1d b0 [2] 39 be [2] 12 92 [2] 3c b0 [2] 28 ab [2] 27 b1 [2] 39 ac [2] 3b ad [2] 20 ab [2] 3c ac [2] 20 83 }

  condition:
    any of them
}