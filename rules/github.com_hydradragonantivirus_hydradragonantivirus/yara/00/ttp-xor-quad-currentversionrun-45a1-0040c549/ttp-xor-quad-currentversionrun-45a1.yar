rule TTP_XOR_QUAD_CurrentVersionRun_45a1 {
  strings:
    $key_45a1 = { 16 ce [2] 32 c0 [2] 19 ec [2] 37 ce [2] 23 d5 [2] 2c cf [2] 32 d2 [2] 30 d3 [2] 2b d5 [2] 37 d2 [2] 2b fd }

  condition:
    any of them
}