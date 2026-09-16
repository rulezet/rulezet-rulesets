rule TTP_XOR_QUAD_CurrentVersionRun_3fbd {
  strings:
    $key_3fbd = { 6c d2 [2] 48 dc [2] 63 f0 [2] 4d d2 [2] 59 c9 [2] 56 d3 [2] 48 ce [2] 4a cf [2] 51 c9 [2] 4d ce [2] 51 e1 }

  condition:
    any of them
}