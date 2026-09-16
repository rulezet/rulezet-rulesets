rule TTP_XOR_QUAD_CurrentVersionRun_37a1 {
  strings:
    $key_37a1 = { 64 ce [2] 40 c0 [2] 6b ec [2] 45 ce [2] 51 d5 [2] 5e cf [2] 40 d2 [2] 42 d3 [2] 59 d5 [2] 45 d2 [2] 59 fd }

  condition:
    any of them
}