rule TTP_XOR_QUAD_CurrentVersionRun_2bdf {
  strings:
    $key_2bdf = { 78 b0 [2] 5c be [2] 77 92 [2] 59 b0 [2] 4d ab [2] 42 b1 [2] 5c ac [2] 5e ad [2] 45 ab [2] 59 ac [2] 45 83 }

  condition:
    any of them
}