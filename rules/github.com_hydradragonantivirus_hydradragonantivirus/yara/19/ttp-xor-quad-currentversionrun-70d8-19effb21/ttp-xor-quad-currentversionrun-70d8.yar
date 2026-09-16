rule TTP_XOR_QUAD_CurrentVersionRun_70d8 {
  strings:
    $key_70d8 = { 23 b7 [2] 07 b9 [2] 2c 95 [2] 02 b7 [2] 16 ac [2] 19 b6 [2] 07 ab [2] 05 aa [2] 1e ac [2] 02 ab [2] 1e 84 }

  condition:
    any of them
}