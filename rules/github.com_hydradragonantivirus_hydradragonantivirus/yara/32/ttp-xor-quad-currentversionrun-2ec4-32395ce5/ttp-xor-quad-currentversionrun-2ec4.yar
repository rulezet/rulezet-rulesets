rule TTP_XOR_QUAD_CurrentVersionRun_2ec4 {
  strings:
    $key_2ec4 = { 7d ab [2] 59 a5 [2] 72 89 [2] 5c ab [2] 48 b0 [2] 47 aa [2] 59 b7 [2] 5b b6 [2] 40 b0 [2] 5c b7 [2] 40 98 }

  condition:
    any of them
}