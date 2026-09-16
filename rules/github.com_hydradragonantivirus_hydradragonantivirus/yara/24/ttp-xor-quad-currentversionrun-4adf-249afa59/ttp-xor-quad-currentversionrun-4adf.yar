rule TTP_XOR_QUAD_CurrentVersionRun_4adf {
  strings:
    $key_4adf = { 19 b0 [2] 3d be [2] 16 92 [2] 38 b0 [2] 2c ab [2] 23 b1 [2] 3d ac [2] 3f ad [2] 24 ab [2] 38 ac [2] 24 83 }

  condition:
    any of them
}