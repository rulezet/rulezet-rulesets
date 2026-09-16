rule TTP_XOR_QUAD_CurrentVersionRun_7ec4 {
  strings:
    $key_7ec4 = { 2d ab [2] 09 a5 [2] 22 89 [2] 0c ab [2] 18 b0 [2] 17 aa [2] 09 b7 [2] 0b b6 [2] 10 b0 [2] 0c b7 [2] 10 98 }

  condition:
    any of them
}