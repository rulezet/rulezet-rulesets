rule TTP_XOR_QUAD_CurrentVersionRun_73a1 {
  strings:
    $key_73a1 = { 20 ce [2] 04 c0 [2] 2f ec [2] 01 ce [2] 15 d5 [2] 1a cf [2] 04 d2 [2] 06 d3 [2] 1d d5 [2] 01 d2 [2] 1d fd }

  condition:
    any of them
}