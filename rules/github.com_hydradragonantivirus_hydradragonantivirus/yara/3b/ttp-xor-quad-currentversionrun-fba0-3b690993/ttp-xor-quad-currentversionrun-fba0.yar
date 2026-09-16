rule TTP_XOR_QUAD_CurrentVersionRun_fba0 {
  strings:
    $key_fba0 = { a8 cf [2] 8c c1 [2] a7 ed [2] 89 cf [2] 9d d4 [2] 92 ce [2] 8c d3 [2] 8e d2 [2] 95 d4 [2] 89 d3 [2] 95 fc }

  condition:
    any of them
}