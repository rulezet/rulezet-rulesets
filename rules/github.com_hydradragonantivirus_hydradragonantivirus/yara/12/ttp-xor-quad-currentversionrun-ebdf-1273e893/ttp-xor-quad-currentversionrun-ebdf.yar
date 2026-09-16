rule TTP_XOR_QUAD_CurrentVersionRun_ebdf {
  strings:
    $key_ebdf = { b8 b0 [2] 9c be [2] b7 92 [2] 99 b0 [2] 8d ab [2] 82 b1 [2] 9c ac [2] 9e ad [2] 85 ab [2] 99 ac [2] 85 83 }

  condition:
    any of them
}