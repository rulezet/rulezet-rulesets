rule TTP_XOR_QUAD_CurrentVersionRun_f9a0 {
  strings:
    $key_f9a0 = { aa cf [2] 8e c1 [2] a5 ed [2] 8b cf [2] 9f d4 [2] 90 ce [2] 8e d3 [2] 8c d2 [2] 97 d4 [2] 8b d3 [2] 97 fc }

  condition:
    any of them
}