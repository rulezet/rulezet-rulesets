rule TTP_XOR_QUAD_CurrentVersionRun_e9a0 {
  strings:
    $key_e9a0 = { ba cf [2] 9e c1 [2] b5 ed [2] 9b cf [2] 8f d4 [2] 80 ce [2] 9e d3 [2] 9c d2 [2] 87 d4 [2] 9b d3 [2] 87 fc }

  condition:
    any of them
}