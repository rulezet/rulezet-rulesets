rule TTP_XOR_QUAD_CurrentVersionRun_21bd {
  strings:
    $key_21bd = { 72 d2 [2] 56 dc [2] 7d f0 [2] 53 d2 [2] 47 c9 [2] 48 d3 [2] 56 ce [2] 54 cf [2] 4f c9 [2] 53 ce [2] 4f e1 }

  condition:
    any of them
}