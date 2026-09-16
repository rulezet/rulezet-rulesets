rule TTP_XOR_QUAD_CurrentVersionRun_6fc4 {
  strings:
    $key_6fc4 = { 3c ab [2] 18 a5 [2] 33 89 [2] 1d ab [2] 09 b0 [2] 06 aa [2] 18 b7 [2] 1a b6 [2] 01 b0 [2] 1d b7 [2] 01 98 }

  condition:
    any of them
}