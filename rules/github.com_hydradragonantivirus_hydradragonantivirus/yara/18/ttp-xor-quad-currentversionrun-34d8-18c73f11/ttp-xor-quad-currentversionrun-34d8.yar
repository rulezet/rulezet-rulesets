rule TTP_XOR_QUAD_CurrentVersionRun_34d8 {
  strings:
    $key_34d8 = { 67 b7 [2] 43 b9 [2] 68 95 [2] 46 b7 [2] 52 ac [2] 5d b6 [2] 43 ab [2] 41 aa [2] 5a ac [2] 46 ab [2] 5a 84 }

  condition:
    any of them
}