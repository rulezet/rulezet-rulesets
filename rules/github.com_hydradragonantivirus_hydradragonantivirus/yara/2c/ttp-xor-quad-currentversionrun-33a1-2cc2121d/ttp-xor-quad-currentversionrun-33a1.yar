rule TTP_XOR_QUAD_CurrentVersionRun_33a1 {
  strings:
    $key_33a1 = { 60 ce [2] 44 c0 [2] 6f ec [2] 41 ce [2] 55 d5 [2] 5a cf [2] 44 d2 [2] 46 d3 [2] 5d d5 [2] 41 d2 [2] 5d fd }

  condition:
    any of them
}