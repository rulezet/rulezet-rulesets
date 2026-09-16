rule TTP_XOR_QUAD_CurrentVersionRun_38a0 {
  strings:
    $key_38a0 = { 6b cf [2] 4f c1 [2] 64 ed [2] 4a cf [2] 5e d4 [2] 51 ce [2] 4f d3 [2] 4d d2 [2] 56 d4 [2] 4a d3 [2] 56 fc }

  condition:
    any of them
}