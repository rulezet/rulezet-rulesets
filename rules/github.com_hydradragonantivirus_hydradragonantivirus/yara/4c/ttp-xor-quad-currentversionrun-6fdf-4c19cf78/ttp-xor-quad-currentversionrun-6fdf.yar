rule TTP_XOR_QUAD_CurrentVersionRun_6fdf {
  strings:
    $key_6fdf = { 3c b0 [2] 18 be [2] 33 92 [2] 1d b0 [2] 09 ab [2] 06 b1 [2] 18 ac [2] 1a ad [2] 01 ab [2] 1d ac [2] 01 83 }

  condition:
    any of them
}