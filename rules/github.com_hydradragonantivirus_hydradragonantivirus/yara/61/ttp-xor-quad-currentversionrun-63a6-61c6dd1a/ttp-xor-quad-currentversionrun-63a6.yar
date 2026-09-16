rule TTP_XOR_QUAD_CurrentVersionRun_63a6 {
  strings:
    $key_63a6 = { 30 c9 [2] 14 c7 [2] 3f eb [2] 11 c9 [2] 05 d2 [2] 0a c8 [2] 14 d5 [2] 16 d4 [2] 0d d2 [2] 11 d5 [2] 0d fa }

  condition:
    any of them
}