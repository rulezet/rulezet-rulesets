rule TTP_XOR_QUAD_CurrentVersionRun_03a6 {
  strings:
    $key_03a6 = { 50 c9 [2] 74 c7 [2] 5f eb [2] 71 c9 [2] 65 d2 [2] 6a c8 [2] 74 d5 [2] 76 d4 [2] 6d d2 [2] 71 d5 [2] 6d fa }

  condition:
    any of them
}