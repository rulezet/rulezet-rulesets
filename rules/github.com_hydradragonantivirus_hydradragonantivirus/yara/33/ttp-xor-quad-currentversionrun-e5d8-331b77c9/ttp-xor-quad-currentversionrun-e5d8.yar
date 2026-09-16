rule TTP_XOR_QUAD_CurrentVersionRun_e5d8 {
  strings:
    $key_e5d8 = { b6 b7 [2] 92 b9 [2] b9 95 [2] 97 b7 [2] 83 ac [2] 8c b6 [2] 92 ab [2] 90 aa [2] 8b ac [2] 97 ab [2] 8b 84 }

  condition:
    any of them
}