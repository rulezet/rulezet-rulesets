rule TTP_XOR_QUAD_CurrentVersionRun_71bd {
  strings:
    $key_71bd = { 22 d2 [2] 06 dc [2] 2d f0 [2] 03 d2 [2] 17 c9 [2] 18 d3 [2] 06 ce [2] 04 cf [2] 1f c9 [2] 03 ce [2] 1f e1 }

  condition:
    any of them
}