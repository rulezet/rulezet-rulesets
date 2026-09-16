rule TTP_XOR_QUAD_CurrentVersionRun_61a1 {
  strings:
    $key_61a1 = { 32 ce [2] 16 c0 [2] 3d ec [2] 13 ce [2] 07 d5 [2] 08 cf [2] 16 d2 [2] 14 d3 [2] 0f d5 [2] 13 d2 [2] 0f fd }

  condition:
    any of them
}