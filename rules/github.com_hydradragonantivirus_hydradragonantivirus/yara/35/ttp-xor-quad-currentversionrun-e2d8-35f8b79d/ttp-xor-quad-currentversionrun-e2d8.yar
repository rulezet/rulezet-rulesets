rule TTP_XOR_QUAD_CurrentVersionRun_e2d8 {
  strings:
    $key_e2d8 = { b1 b7 [2] 95 b9 [2] be 95 [2] 90 b7 [2] 84 ac [2] 8b b6 [2] 95 ab [2] 97 aa [2] 8c ac [2] 90 ab [2] 8c 84 }

  condition:
    any of them
}