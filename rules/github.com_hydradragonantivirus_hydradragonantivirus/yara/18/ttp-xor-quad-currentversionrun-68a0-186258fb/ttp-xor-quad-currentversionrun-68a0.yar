rule TTP_XOR_QUAD_CurrentVersionRun_68a0 {
  strings:
    $key_68a0 = { 3b cf [2] 1f c1 [2] 34 ed [2] 1a cf [2] 0e d4 [2] 01 ce [2] 1f d3 [2] 1d d2 [2] 06 d4 [2] 1a d3 [2] 06 fc }

  condition:
    any of them
}