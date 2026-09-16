rule TTP_XOR_QUAD_CurrentVersionRun_22a1 {
  strings:
    $key_22a1 = { 71 ce [2] 55 c0 [2] 7e ec [2] 50 ce [2] 44 d5 [2] 4b cf [2] 55 d2 [2] 57 d3 [2] 4c d5 [2] 50 d2 [2] 4c fd }

  condition:
    any of them
}