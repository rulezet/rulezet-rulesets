rule TTP_XOR_QUAD_CurrentVersionRun_03a1 {
  strings:
    $key_03a1 = { 50 ce [2] 74 c0 [2] 5f ec [2] 71 ce [2] 65 d5 [2] 6a cf [2] 74 d2 [2] 76 d3 [2] 6d d5 [2] 71 d2 [2] 6d fd }

  condition:
    any of them
}