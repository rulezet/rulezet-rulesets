rule TTP_XOR_QUAD_CurrentVersionRun_6ed8 {
  strings:
    $key_6ed8 = { 3d b7 [2] 19 b9 [2] 32 95 [2] 1c b7 [2] 08 ac [2] 07 b6 [2] 19 ab [2] 1b aa [2] 00 ac [2] 1c ab [2] 00 84 }

  condition:
    any of them
}