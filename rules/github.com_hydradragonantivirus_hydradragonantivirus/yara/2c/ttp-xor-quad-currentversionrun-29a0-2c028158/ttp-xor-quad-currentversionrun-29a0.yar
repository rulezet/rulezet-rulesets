rule TTP_XOR_QUAD_CurrentVersionRun_29a0 {
  strings:
    $key_29a0 = { 7a cf [2] 5e c1 [2] 75 ed [2] 5b cf [2] 4f d4 [2] 40 ce [2] 5e d3 [2] 5c d2 [2] 47 d4 [2] 5b d3 [2] 47 fc }

  condition:
    any of them
}