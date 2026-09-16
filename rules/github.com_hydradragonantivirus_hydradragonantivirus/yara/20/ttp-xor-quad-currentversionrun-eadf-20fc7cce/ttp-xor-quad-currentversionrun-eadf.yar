rule TTP_XOR_QUAD_CurrentVersionRun_eadf {
  strings:
    $key_eadf = { b9 b0 [2] 9d be [2] b6 92 [2] 98 b0 [2] 8c ab [2] 83 b1 [2] 9d ac [2] 9f ad [2] 84 ab [2] 98 ac [2] 84 83 }

  condition:
    any of them
}