rule TTP_XOR_QUAD_CurrentVersionRun_1bdf {
  strings:
    $key_1bdf = { 48 b0 [2] 6c be [2] 47 92 [2] 69 b0 [2] 7d ab [2] 72 b1 [2] 6c ac [2] 6e ad [2] 75 ab [2] 69 ac [2] 75 83 }

  condition:
    any of them
}