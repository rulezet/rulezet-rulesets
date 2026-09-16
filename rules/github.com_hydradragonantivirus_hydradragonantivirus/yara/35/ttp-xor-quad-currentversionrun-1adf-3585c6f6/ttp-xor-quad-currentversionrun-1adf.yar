rule TTP_XOR_QUAD_CurrentVersionRun_1adf {
  strings:
    $key_1adf = { 49 b0 [2] 6d be [2] 46 92 [2] 68 b0 [2] 7c ab [2] 73 b1 [2] 6d ac [2] 6f ad [2] 74 ab [2] 68 ac [2] 74 83 }

  condition:
    any of them
}