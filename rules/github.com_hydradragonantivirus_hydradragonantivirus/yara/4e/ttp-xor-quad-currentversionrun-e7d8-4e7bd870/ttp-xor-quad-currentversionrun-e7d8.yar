rule TTP_XOR_QUAD_CurrentVersionRun_e7d8 {
  strings:
    $key_e7d8 = { b4 b7 [2] 90 b9 [2] bb 95 [2] 95 b7 [2] 81 ac [2] 8e b6 [2] 90 ab [2] 92 aa [2] 89 ac [2] 95 ab [2] 89 84 }

  condition:
    any of them
}