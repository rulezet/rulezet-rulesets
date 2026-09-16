rule TTP_XOR_QUAD_CurrentVersionRun_6ea1 {
  strings:
    $key_6ea1 = { 3d ce [2] 19 c0 [2] 32 ec [2] 1c ce [2] 08 d5 [2] 07 cf [2] 19 d2 [2] 1b d3 [2] 00 d5 [2] 1c d2 [2] 00 fd }

  condition:
    any of them
}