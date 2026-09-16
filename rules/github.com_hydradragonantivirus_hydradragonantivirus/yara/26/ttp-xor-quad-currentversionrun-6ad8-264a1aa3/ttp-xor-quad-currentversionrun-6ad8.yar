rule TTP_XOR_QUAD_CurrentVersionRun_6ad8 {
  strings:
    $key_6ad8 = { 39 b7 [2] 1d b9 [2] 36 95 [2] 18 b7 [2] 0c ac [2] 03 b6 [2] 1d ab [2] 1f aa [2] 04 ac [2] 18 ab [2] 04 84 }

  condition:
    any of them
}