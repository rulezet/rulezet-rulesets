rule TTP_XOR_QUAD_CurrentVersionRun_1ec4 {
  strings:
    $key_1ec4 = { 4d ab [2] 69 a5 [2] 42 89 [2] 6c ab [2] 78 b0 [2] 77 aa [2] 69 b7 [2] 6b b6 [2] 70 b0 [2] 6c b7 [2] 70 98 }

  condition:
    any of them
}