rule TTP_XOR_QUAD_CurrentVersionRun_1ad8 {
  strings:
    $key_1ad8 = { 49 b7 [2] 6d b9 [2] 46 95 [2] 68 b7 [2] 7c ac [2] 73 b6 [2] 6d ab [2] 6f aa [2] 74 ac [2] 68 ab [2] 74 84 }

  condition:
    any of them
}