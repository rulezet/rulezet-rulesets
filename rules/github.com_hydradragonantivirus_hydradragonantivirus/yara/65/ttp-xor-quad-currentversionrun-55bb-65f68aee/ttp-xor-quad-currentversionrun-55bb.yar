rule TTP_XOR_QUAD_CurrentVersionRun_55bb {
  strings:
    $key_55bb = { 06 d4 [2] 22 da [2] 09 f6 [2] 27 d4 [2] 33 cf [2] 3c d5 [2] 22 c8 [2] 20 c9 [2] 3b cf [2] 27 c8 [2] 3b e7 }

  condition:
    any of them
}