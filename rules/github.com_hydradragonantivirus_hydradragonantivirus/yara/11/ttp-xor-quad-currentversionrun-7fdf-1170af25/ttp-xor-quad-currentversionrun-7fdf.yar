rule TTP_XOR_QUAD_CurrentVersionRun_7fdf {
  strings:
    $key_7fdf = { 2c b0 [2] 08 be [2] 23 92 [2] 0d b0 [2] 19 ab [2] 16 b1 [2] 08 ac [2] 0a ad [2] 11 ab [2] 0d ac [2] 11 83 }

  condition:
    any of them
}