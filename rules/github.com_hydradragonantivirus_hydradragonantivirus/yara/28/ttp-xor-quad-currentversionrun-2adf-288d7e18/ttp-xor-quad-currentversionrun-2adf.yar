rule TTP_XOR_QUAD_CurrentVersionRun_2adf {
  strings:
    $key_2adf = { 79 b0 [2] 5d be [2] 76 92 [2] 58 b0 [2] 4c ab [2] 43 b1 [2] 5d ac [2] 5f ad [2] 44 ab [2] 58 ac [2] 44 83 }

  condition:
    any of them
}