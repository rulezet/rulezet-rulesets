rule TTP_XOR_QUAD_CurrentVersionRun_1ed8 {
  strings:
    $key_1ed8 = { 4d b7 [2] 69 b9 [2] 42 95 [2] 6c b7 [2] 78 ac [2] 77 b6 [2] 69 ab [2] 6b aa [2] 70 ac [2] 6c ab [2] 70 84 }

  condition:
    any of them
}