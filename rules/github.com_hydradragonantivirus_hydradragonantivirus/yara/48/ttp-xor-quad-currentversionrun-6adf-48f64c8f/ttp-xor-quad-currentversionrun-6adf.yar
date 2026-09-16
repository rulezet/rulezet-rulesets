rule TTP_XOR_QUAD_CurrentVersionRun_6adf {
  strings:
    $key_6adf = { 39 b0 [2] 1d be [2] 36 92 [2] 18 b0 [2] 0c ab [2] 03 b1 [2] 1d ac [2] 1f ad [2] 04 ab [2] 18 ac [2] 04 83 }

  condition:
    any of them
}