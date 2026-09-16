rule TTP_XOR_QUAD_CurrentVersionRun_13a6 {
  strings:
    $key_13a6 = { 40 c9 [2] 64 c7 [2] 4f eb [2] 61 c9 [2] 75 d2 [2] 7a c8 [2] 64 d5 [2] 66 d4 [2] 7d d2 [2] 61 d5 [2] 7d fa }

  condition:
    any of them
}