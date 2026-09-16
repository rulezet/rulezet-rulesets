rule TTP_XOR_QUAD_CurrentVersionRun_53a1 {
  strings:
    $key_53a1 = { 00 ce [2] 24 c0 [2] 0f ec [2] 21 ce [2] 35 d5 [2] 3a cf [2] 24 d2 [2] 26 d3 [2] 3d d5 [2] 21 d2 [2] 3d fd }

  condition:
    any of them
}