rule TTP_XOR_QUAD_CurrentVersionRun_78bc {
  strings:
    $key_78bc = { 2b d3 [2] 0f dd [2] 24 f1 [2] 0a d3 [2] 1e c8 [2] 11 d2 [2] 0f cf [2] 0d ce [2] 16 c8 [2] 0a cf [2] 16 e0 }

  condition:
    any of them
}