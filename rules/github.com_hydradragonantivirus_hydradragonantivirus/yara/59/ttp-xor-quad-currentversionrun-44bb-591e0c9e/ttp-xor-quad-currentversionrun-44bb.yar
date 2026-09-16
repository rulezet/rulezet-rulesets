rule TTP_XOR_QUAD_CurrentVersionRun_44bb {
  strings:
    $key_44bb = { 17 d4 [2] 33 da [2] 18 f6 [2] 36 d4 [2] 22 cf [2] 2d d5 [2] 33 c8 [2] 31 c9 [2] 2a cf [2] 36 c8 [2] 2a e7 }

  condition:
    any of them
}