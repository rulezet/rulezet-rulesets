rule TTP_XOR_QUAD_CurrentVersionRun_61bd {
  strings:
    $key_61bd = { 32 d2 [2] 16 dc [2] 3d f0 [2] 13 d2 [2] 07 c9 [2] 08 d3 [2] 16 ce [2] 14 cf [2] 0f c9 [2] 13 ce [2] 0f e1 }

  condition:
    any of them
}