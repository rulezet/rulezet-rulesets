rule TTP_XOR_QUAD_CurrentVersionRun_69a0 {
  strings:
    $key_69a0 = { 3a cf [2] 1e c1 [2] 35 ed [2] 1b cf [2] 0f d4 [2] 00 ce [2] 1e d3 [2] 1c d2 [2] 07 d4 [2] 1b d3 [2] 07 fc }

  condition:
    any of them
}