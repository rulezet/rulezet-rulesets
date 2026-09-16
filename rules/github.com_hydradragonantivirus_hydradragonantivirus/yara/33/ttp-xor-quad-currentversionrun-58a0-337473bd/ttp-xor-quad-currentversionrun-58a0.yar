rule TTP_XOR_QUAD_CurrentVersionRun_58a0 {
  strings:
    $key_58a0 = { 0b cf [2] 2f c1 [2] 04 ed [2] 2a cf [2] 3e d4 [2] 31 ce [2] 2f d3 [2] 2d d2 [2] 36 d4 [2] 2a d3 [2] 36 fc }

  condition:
    any of them
}