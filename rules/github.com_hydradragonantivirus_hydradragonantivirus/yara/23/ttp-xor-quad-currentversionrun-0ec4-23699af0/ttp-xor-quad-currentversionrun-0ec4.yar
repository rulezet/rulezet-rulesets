rule TTP_XOR_QUAD_CurrentVersionRun_0ec4 {
  strings:
    $key_0ec4 = { 5d ab [2] 79 a5 [2] 52 89 [2] 7c ab [2] 68 b0 [2] 67 aa [2] 79 b7 [2] 7b b6 [2] 60 b0 [2] 7c b7 [2] 60 98 }

  condition:
    any of them
}