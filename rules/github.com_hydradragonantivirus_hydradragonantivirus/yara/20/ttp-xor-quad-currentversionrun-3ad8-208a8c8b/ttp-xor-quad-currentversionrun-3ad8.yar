rule TTP_XOR_QUAD_CurrentVersionRun_3ad8 {
  strings:
    $key_3ad8 = { 69 b7 [2] 4d b9 [2] 66 95 [2] 48 b7 [2] 5c ac [2] 53 b6 [2] 4d ab [2] 4f aa [2] 54 ac [2] 48 ab [2] 54 84 }

  condition:
    any of them
}