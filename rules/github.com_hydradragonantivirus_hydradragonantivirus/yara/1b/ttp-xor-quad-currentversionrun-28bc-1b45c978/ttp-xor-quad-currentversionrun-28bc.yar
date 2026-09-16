rule TTP_XOR_QUAD_CurrentVersionRun_28bc {
  strings:
    $key_28bc = { 7b d3 [2] 5f dd [2] 74 f1 [2] 5a d3 [2] 4e c8 [2] 41 d2 [2] 5f cf [2] 5d ce [2] 46 c8 [2] 5a cf [2] 46 e0 }

  condition:
    any of them
}