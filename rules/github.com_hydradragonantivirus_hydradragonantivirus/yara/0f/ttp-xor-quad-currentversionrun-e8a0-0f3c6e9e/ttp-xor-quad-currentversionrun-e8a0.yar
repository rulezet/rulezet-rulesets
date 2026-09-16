rule TTP_XOR_QUAD_CurrentVersionRun_e8a0 {
  strings:
    $key_e8a0 = { bb cf [2] 9f c1 [2] b4 ed [2] 9a cf [2] 8e d4 [2] 81 ce [2] 9f d3 [2] 9d d2 [2] 86 d4 [2] 9a d3 [2] 86 fc }

  condition:
    any of them
}