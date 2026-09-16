rule TTP_XOR_QUAD_CurrentVersionRun_eca0 {
  strings:
    $key_eca0 = { bf cf [2] 9b c1 [2] b0 ed [2] 9e cf [2] 8a d4 [2] 85 ce [2] 9b d3 [2] 99 d2 [2] 82 d4 [2] 9e d3 [2] 82 fc }

  condition:
    any of them
}