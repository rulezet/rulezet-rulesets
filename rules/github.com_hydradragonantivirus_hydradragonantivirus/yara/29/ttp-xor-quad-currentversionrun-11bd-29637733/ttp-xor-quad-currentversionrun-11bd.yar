rule TTP_XOR_QUAD_CurrentVersionRun_11bd {
  strings:
    $key_11bd = { 42 d2 [2] 66 dc [2] 4d f0 [2] 63 d2 [2] 77 c9 [2] 78 d3 [2] 66 ce [2] 64 cf [2] 7f c9 [2] 63 ce [2] 7f e1 }

  condition:
    any of them
}