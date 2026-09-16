rule TTP_XOR_QUAD_CurrentVersionRun_0adf {
  strings:
    $key_0adf = { 59 b0 [2] 7d be [2] 56 92 [2] 78 b0 [2] 6c ab [2] 63 b1 [2] 7d ac [2] 7f ad [2] 64 ab [2] 78 ac [2] 64 83 }

  condition:
    any of them
}