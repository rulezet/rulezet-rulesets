rule TTP_XOR_QUAD_CurrentVersionRun_04bb {
  strings:
    $key_04bb = { 57 d4 [2] 73 da [2] 58 f6 [2] 76 d4 [2] 62 cf [2] 6d d5 [2] 73 c8 [2] 71 c9 [2] 6a cf [2] 76 c8 [2] 6a e7 }

  condition:
    any of them
}