rule TTP_XOR_QUAD_CurrentVersionRun_48a0 {
  strings:
    $key_48a0 = { 1b cf [2] 3f c1 [2] 14 ed [2] 3a cf [2] 2e d4 [2] 21 ce [2] 3f d3 [2] 3d d2 [2] 26 d4 [2] 3a d3 [2] 26 fc }

  condition:
    any of them
}