rule TTP_XOR_QUAD_CurrentVersionRun_65bb {
  strings:
    $key_65bb = { 36 d4 [2] 12 da [2] 39 f6 [2] 17 d4 [2] 03 cf [2] 0c d5 [2] 12 c8 [2] 10 c9 [2] 0b cf [2] 17 c8 [2] 0b e7 }

  condition:
    any of them
}