rule TTP_XOR_QUAD_CurrentVersionRun_2fc4 {
  strings:
    $key_2fc4 = { 7c ab [2] 58 a5 [2] 73 89 [2] 5d ab [2] 49 b0 [2] 46 aa [2] 58 b7 [2] 5a b6 [2] 41 b0 [2] 5d b7 [2] 41 98 }

  condition:
    any of them
}