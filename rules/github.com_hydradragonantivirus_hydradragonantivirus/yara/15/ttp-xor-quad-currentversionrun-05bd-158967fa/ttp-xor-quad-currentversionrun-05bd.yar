rule TTP_XOR_QUAD_CurrentVersionRun_05bd {
  strings:
    $key_05bd = { 56 d2 [2] 72 dc [2] 59 f0 [2] 77 d2 [2] 63 c9 [2] 6c d3 [2] 72 ce [2] 70 cf [2] 6b c9 [2] 77 ce [2] 6b e1 }

  condition:
    any of them
}