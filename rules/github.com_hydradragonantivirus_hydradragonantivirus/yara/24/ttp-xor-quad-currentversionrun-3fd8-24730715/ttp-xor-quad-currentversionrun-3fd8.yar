rule TTP_XOR_QUAD_CurrentVersionRun_3fd8 {
  strings:
    $key_3fd8 = { 6c b7 [2] 48 b9 [2] 63 95 [2] 4d b7 [2] 59 ac [2] 56 b6 [2] 48 ab [2] 4a aa [2] 51 ac [2] 4d ab [2] 51 84 }

  condition:
    any of them
}