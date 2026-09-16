rule TTP_XOR_QUAD_CurrentVersionRun_1fc4 {
  strings:
    $key_1fc4 = { 4c ab [2] 68 a5 [2] 43 89 [2] 6d ab [2] 79 b0 [2] 76 aa [2] 68 b7 [2] 6a b6 [2] 71 b0 [2] 6d b7 [2] 71 98 }

  condition:
    any of them
}