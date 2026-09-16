rule TTP_XOR_QUAD_CurrentVersionRun_35a1 {
  strings:
    $key_35a1 = { 66 ce [2] 42 c0 [2] 69 ec [2] 47 ce [2] 53 d5 [2] 5c cf [2] 42 d2 [2] 40 d3 [2] 5b d5 [2] 47 d2 [2] 5b fd }

  condition:
    any of them
}