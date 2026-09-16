rule TTP_XOR_QUAD_CurrentVersionRun_1edf {
  strings:
    $key_1edf = { 4d b0 [2] 69 be [2] 42 92 [2] 6c b0 [2] 78 ab [2] 77 b1 [2] 69 ac [2] 6b ad [2] 70 ab [2] 6c ac [2] 70 83 }

  condition:
    any of them
}