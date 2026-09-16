rule TTP_XOR_QUAD_CurrentVersionRun_54c5 {
  strings:
    $key_54c5 = { 07 aa [2] 23 a4 [2] 08 88 [2] 26 aa [2] 32 b1 [2] 3d ab [2] 23 b6 [2] 21 b7 [2] 3a b1 [2] 26 b6 [2] 3a 99 }

  condition:
    any of them
}