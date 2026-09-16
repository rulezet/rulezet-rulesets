rule TTP_XOR_QUAD_CurrentVersionRun_05a1 {
  strings:
    $key_05a1 = { 56 ce [2] 72 c0 [2] 59 ec [2] 77 ce [2] 63 d5 [2] 6c cf [2] 72 d2 [2] 70 d3 [2] 6b d5 [2] 77 d2 [2] 6b fd }

  condition:
    any of them
}