rule TTP_XOR_QUAD_CurrentVersionRun_33a6 {
  strings:
    $key_33a6 = { 60 c9 [2] 44 c7 [2] 6f eb [2] 41 c9 [2] 55 d2 [2] 5a c8 [2] 44 d5 [2] 46 d4 [2] 5d d2 [2] 41 d5 [2] 5d fa }

  condition:
    any of them
}